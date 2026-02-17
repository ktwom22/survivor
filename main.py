import os, uuid, requests, csv
from io import StringIO
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "survivor_2026_pro_key")

# --- DATABASE CONFIG (RAILWAY FRIENDLY) ---
# Railway uses 'postgres://', but SQLAlchemy 1.4+ requires 'postgresql://'
db_url = os.getenv("DATABASE_URL")
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url or 'sqlite:///survivor_v5.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# --- MODELS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    rosters = db.relationship('Roster', backref='owner', cascade="all, delete-orphan", lazy=True)


class Survivor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    image_url = db.Column(db.String(500))
    season = db.Column(db.String(100))
    details = db.Column(db.Text)
    points = db.Column(db.Float, default=0.0)
    is_out = db.Column(db.Boolean, default=False)
    stats = db.relationship('WeeklyStat', backref='player', lazy=True)


class WeeklyStat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    player_id = db.Column(db.Integer, db.ForeignKey('survivor.id'))
    week = db.Column(db.Integer)
    surv = db.Column(db.Float, default=0.0)
    imm = db.Column(db.Float, default=0.0)
    idl = db.Column(db.Float, default=0.0)
    soc = db.Column(db.Float, default=0.0)
    pnl = db.Column(db.Float, default=0.0)

    @property
    def week_total(self):
        return self.surv + self.imm + self.idl + self.soc + self.pnl


class League(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    invite_code = db.Column(db.String(10), unique=True)


class Roster(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    league_id = db.Column(db.Integer, db.ForeignKey('league.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    cap1_id = db.Column(db.Integer)
    cap2_id = db.Column(db.Integer)
    cap3_id = db.Column(db.Integer)
    regular_ids = db.Column(db.String(100))


# --- HELPERS ---
def sync_players():
    url = "https://docs.google.com/spreadsheets/d/e/2PACX-1vQoYLaaQ7OnWbEiHpJo27v0PUzp6r_ufLCHgpYB5kdHluNOgQilvIsZNU_pp78nda4Jd5Vislg1VYbO/pub?gid=0&single=true&output=csv"
    try:
        r = requests.get(url)
        r.encoding = 'utf-8'
        reader = csv.DictReader(StringIO(r.text))
        for row in reader:
            name = row.get('Name', '').strip()
            img = row.get('Image Link', '').strip()
            seas = row.get('What Season?', '').strip()
            desc = row.get('Details', '').strip()
            if not name: continue

            p = Survivor.query.filter_by(name=name).first()
            if not p:
                p = Survivor(name=name, image_url=img, season=seas, details=desc)
                db.session.add(p)
            else:
                p.image_url = img
                p.season = seas
                p.details = desc
        db.session.commit()
    except Exception as e:
        print(f"Sync error: {e}")


def get_roster_data(roster):
    if not roster: return None
    # Using session.get for SQLAlchemy 2.0 compatibility
    c1 = db.session.get(Survivor, roster.cap1_id)
    c2 = db.session.get(Survivor, roster.cap2_id)
    c3 = db.session.get(Survivor, roster.cap3_id)
    regs = []
    if roster.regular_ids:
        for rid in roster.regular_ids.split(','):
            if rid.strip().isdigit():
                p = db.session.get(Survivor, int(rid))
                if p: regs.append(p)
    return {"cap1": c1, "cap2": c2, "cap3": c3, "regs": regs}


# --- ROUTES ---
@app.before_request
def setup_database():
    # This checks if we've already initialized this server instance
    if not hasattr(app, "_database_initialized"):
        with app.app_context():
            db.create_all()  # Creates User, Survivor, League tables in Postgres
            # Only sync if database is empty to prevent slow startups
            if Survivor.query.count() == 0:
                sync_players()
        app._database_initialized = True

@app.route('/')
def home():
    leagues = []
    if 'user_id' in session:
        my_rosters = Roster.query.filter_by(user_id=session['user_id']).all()
        league_ids = [r.league_id for r in my_rosters]
        leagues = League.query.filter(League.id.in_(league_ids)).all()
    return render_template('home.html', user_leagues=leagues)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        hashed_pw = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        new_u = User(username=request.form['username'], email=request.form['email'], password=hashed_pw)
        try:
            db.session.add(new_u)
            db.session.commit()
            return redirect(url_for('login'))
        except:
            db.session.rollback()
            flash("Username or Email already exists.")
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = User.query.filter_by(email=request.form['email']).first()
        if u and check_password_hash(u.password, request.form['password']):
            session['user_id'], session['username'] = u.id, u.username
            return redirect(url_for('home'))
        flash("Invalid credentials.")
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


@app.route('/create_league', methods=['POST'])
def create_league():
    if 'user_id' not in session: return redirect(url_for('login'))
    code = str(uuid.uuid4())[:6].upper()
    new_l = League(name=request.form.get('league_name', 'New League'), invite_code=code)
    db.session.add(new_l)
    db.session.commit()
    return redirect(url_for('league_dashboard', code=code))


@app.route('/join_league', methods=['POST'])
def join_league():
    if 'user_id' not in session: return redirect(url_for('login'))
    code = request.form.get('invite_code', '').upper().strip()
    l = League.query.filter_by(invite_code=code).first()
    if l: return redirect(url_for('league_dashboard', code=code))
    flash("League not found.")
    return redirect(url_for('home'))


@app.route('/league/<code>')
def league_dashboard(code):
    if 'user_id' not in session: return redirect(url_for('login'))
    league = League.query.filter_by(invite_code=code).first_or_404()
    target_username = request.args.get('view_user', session.get('username'))

    all_rosters = Roster.query.filter_by(league_id=league.id).all()
    leaderboard = []
    for r in all_rosters:
        if not r.owner: continue
        score = 0.0
        data = get_roster_data(r)
        if data['cap1']: score += (data['cap1'].points * 2.0)
        if data['cap2']: score += (data['cap2'].points * 1.5)
        if data['cap3']: score += (data['cap3'].points * 1.25)
        for p in data['regs']: score += p.points
        leaderboard.append({'user': r.owner.username, 'score': round(score, 1)})

    leaderboard = sorted(leaderboard, key=lambda x: x['score'], reverse=True)
    target_user = User.query.filter_by(username=target_username).first()
    display_roster = Roster.query.filter_by(league_id=league.id, user_id=target_user.id).first() if target_user else None

    # Draft Filtering
    taken_ids = []
    for r in all_rosters:
        taken_ids.extend([r.cap1_id, r.cap2_id, r.cap3_id])
        if r.regular_ids:
            taken_ids.extend([int(x) for x in r.regular_ids.split(',') if x.strip()])

    available = Survivor.query.filter(
        ~Survivor.id.in_([tid for tid in taken_ids if tid]),
        Survivor.is_out == False
    ).all()

    return render_template('dashboard.html',
                           league=league,
                           leaderboard=leaderboard,
                           my_tribe=get_roster_data(display_roster),
                           target_username=target_username,
                           available=available)


@app.route('/draft/<code>', methods=['POST'])
def draft(code):
    if 'user_id' not in session: return redirect(url_for('login'))
    league = League.query.filter_by(invite_code=code).first_or_404()
    existing = Roster.query.filter_by(league_id=league.id, user_id=session['user_id']).first()
    if existing: return redirect(url_for('league_dashboard', code=code))

    try:
        new_r = Roster(
            league_id=league.id,
            user_id=session['user_id'],
            cap1_id=int(request.form.get('cap1')) if request.form.get('cap1') else None,
            cap2_id=int(request.form.get('cap2')) if request.form.get('cap2') else None,
            cap3_id=int(request.form.get('cap3')) if request.form.get('cap3') else None,
            regular_ids=",".join(request.form.getlist('regs'))
        )
        db.session.add(new_r)
        db.session.commit()
    except:
        db.session.rollback()
    return redirect(url_for('league_dashboard', code=code))


@app.route('/admin/scoring', methods=['GET', 'POST'])
def admin_scoring():
    survivors = Survivor.query.all()
    if request.method == 'POST':
        week_num = int(request.form.get('week_num', 1))
        for s in survivors:
            if request.form.get(f'voted_out_{s.id}'):
                s.is_out = True
            stat = WeeklyStat(
                player_id=s.id, week=week_num,
                surv=float(request.form.get(f'surv_{s.id}', 0)),
                imm=float(request.form.get(f'imm_{s.id}', 0)),
                idl=float(request.form.get(f'idl_{s.id}', 0)),
                soc=float(request.form.get(f'soc_{s.id}', 0)),
                pnl=float(request.form.get(f'pnl_{s.id}', 0))
            )
            s.points += stat.week_total
            db.session.add(stat)
        db.session.commit()
        return redirect(url_for('admin_scoring'))
    return render_template('admin_scoring.html', survivors=survivors)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        sync_players()
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)