import os, uuid, requests, csv
from io import StringIO
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "survivor_2026_pro_key")

# --- DATABASE CONFIG ---
db_url = os.getenv("DATABASE_URL")
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

# Incremented to v6 to handle the new Boolean scoring columns
app.config['SQLALCHEMY_DATABASE_URI'] = db_url or 'sqlite:///survivor_v6.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- RECALIBRATED SCORING CONFIG ---
POINTS_CONFIG = {
    "survive_episode": 2.0,
    "win_immunity": 5.0,
    "win_reward": 2.0,
    "found_advantage": 4.0,
    "made_merge": 5.0,
    "final_five": 8.0,
    "final_three": 12.0,
    "winner": 20.0,
    "confessional_cry": 2.0,
    "penalty": -2.0,
    "quit_game": -25.0
}


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

    # New Checkbox-based Boolean fields
    survived = db.Column(db.Boolean, default=False)
    immunity = db.Column(db.Boolean, default=False)
    reward = db.Column(db.Boolean, default=False)
    advantage = db.Column(db.Boolean, default=False)
    merge = db.Column(db.Boolean, default=False)
    f5 = db.Column(db.Boolean, default=False)
    f3 = db.Column(db.Boolean, default=False)
    winner = db.Column(db.Boolean, default=False)
    crying = db.Column(db.Boolean, default=False)
    penalty = db.Column(db.Boolean, default=False)
    quit = db.Column(db.Boolean, default=False)

    @property
    def week_total(self):
        t = 0
        if self.survived:  t += POINTS_CONFIG["survive_episode"]
        if self.immunity:  t += POINTS_CONFIG["win_immunity"]
        if self.reward:    t += POINTS_CONFIG["win_reward"]
        if self.advantage: t += POINTS_CONFIG["found_advantage"]
        if self.merge:     t += POINTS_CONFIG["made_merge"]
        if self.f5:        t += POINTS_CONFIG["final_five"]
        if self.f3:        t += POINTS_CONFIG["final_three"]
        if self.winner:    t += POINTS_CONFIG["winner"]
        if self.crying:    t += POINTS_CONFIG["confessional_cry"]
        if self.penalty:   t += POINTS_CONFIG["penalty"]
        if self.quit:      t += POINTS_CONFIG["quit_game"]
        return t


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
                p.image_url, p.season, p.details = img, seas, desc
        db.session.commit()
    except Exception as e:
        print(f"Sync error: {e}")


def get_roster_data(roster):
    if not roster: return None
    c1 = db.session.get(Survivor, roster.cap1_id) if roster.cap1_id else None
    c2 = db.session.get(Survivor, roster.cap2_id) if roster.cap2_id else None
    c3 = db.session.get(Survivor, roster.cap3_id) if roster.cap3_id else None
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
    if not hasattr(app, "_database_initialized"):
        with app.app_context():
            db.create_all()
            if Survivor.query.count() == 0: sync_players()
        app._database_initialized = True


@app.route('/')
def home():
    all_cast = Survivor.query.all()
    leagues = []
    if 'user_id' in session:
        my_rosters = Roster.query.filter_by(user_id=session['user_id']).all()
        league_ids = [r.league_id for r in my_rosters]
        if league_ids: leagues = League.query.filter(League.id.in_(league_ids)).all()
    return render_template('home.html', user_leagues=leagues, cast=all_cast)


@app.route('/player/<int:player_id>')
def player_profile(player_id):
    p_obj = db.session.get(Survivor, player_id)
    if not p_obj: return redirect(url_for('home'))
    # Calculate totals based on boolean occurrences
    totals = {
        'surv': sum(1 for s in p_obj.stats if s.survived),
        'imm': sum(1 for s in p_obj.stats if s.immunity),
        'adv': sum(1 for s in p_obj.stats if s.advantage),
        'cry': sum(1 for s in p_obj.stats if s.crying),
        'score': p_obj.points
    }
    return render_template('player_profile.html', p=p_obj, totals=totals)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username, email, password = request.form.get('username'), request.form.get('email'), request.form.get(
            'password')
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_u = User(username=username, email=email, password=hashed_pw)
        try:
            db.session.add(new_u)
            db.session.commit()
            session['user_id'], session['username'] = new_u.id, new_u.username
            return redirect(url_for('home'))
        except:
            db.session.rollback(); flash("Username/Email exists.")
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = User.query.filter(
            (User.email == request.form.get('email')) | (User.username == request.form.get('email'))).first()
        if u and check_password_hash(u.password, request.form.get('password')):
            session['user_id'], session['username'] = u.id, u.username
            return redirect(url_for('home'))
        flash("Invalid credentials.")
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear();
    return redirect(url_for('home'))


@app.route('/create_league', methods=['POST'])
def create_league():
    if 'user_id' not in session: return redirect(url_for('login'))
    code = str(uuid.uuid4())[:6].upper()
    new_l = League(name=request.form.get('league_name', 'New League'), invite_code=code)
    db.session.add(new_l)
    db.session.flush()
    db.session.add(Roster(league_id=new_l.id, user_id=session['user_id']))
    db.session.commit()
    return redirect(url_for('league_success', code=code))


@app.route('/league-created/<code>')
def league_success(code):
    league = League.query.filter_by(invite_code=code).first_or_404()
    return render_template('league_success.html', league=league)


@app.route('/join_league', methods=['POST'])
def join_league():
    if 'user_id' not in session: return redirect(url_for('login'))
    l = League.query.filter_by(invite_code=request.form.get('invite_code', '').upper().strip()).first()
    if l:
        if not Roster.query.filter_by(league_id=l.id, user_id=session['user_id']).first():
            db.session.add(Roster(league_id=l.id, user_id=session['user_id']))
            db.session.commit()
        return redirect(url_for('league_dashboard', code=l.invite_code))
    flash("League not found.");
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
        is_drafting = (r.cap1_id is None)
        score = 0.0
        if not is_drafting:
            d = get_roster_data(r)
            score += (d['cap1'].points * 2.0) + (d['cap2'].points * 1.5) + (d['cap3'].points * 1.25)
            score += sum(p.points for p in d['regs'])
        leaderboard.append({'user': r.owner.username, 'score': round(score, 1), 'is_drafting': is_drafting})

    leaderboard = sorted(leaderboard, key=lambda x: x['score'], reverse=True)
    target_user = User.query.filter_by(username=target_username).first()
    disp_r = Roster.query.filter_by(league_id=league.id, user_id=target_user.id).first() if target_user else None

    taken = []
    for r in all_rosters:
        taken.extend([r.cap1_id, r.cap2_id, r.cap3_id])
        if r.regular_ids: taken.extend([int(x) for x in r.regular_ids.split(',') if x.strip()])

    available = Survivor.query.filter(~Survivor.id.in_([t for t in taken if t]), Survivor.is_out == False).all()
    return render_template('dashboard.html', league=league, leaderboard=leaderboard, my_tribe=get_roster_data(disp_r),
                           target_username=target_username, available=available)


@app.route('/draft/<code>', methods=['POST'])
def draft(code):
    if 'user_id' not in session: return redirect(url_for('login'))
    l = League.query.filter_by(invite_code=code).first_or_404()
    r = Roster.query.filter_by(league_id=l.id, user_id=session['user_id']).first()
    if r:
        r.cap1_id, r.cap2_id, r.cap3_id = int(request.form.get('cap1')), int(request.form.get('cap2')), int(
            request.form.get('cap3'))
        r.regular_ids = ",".join(request.form.getlist('regs'))
        db.session.commit()
    return redirect(url_for('league_dashboard', code=code))


@app.route('/admin/scoring', methods=['GET', 'POST'])
def admin_scoring():
    # 1. Check if already authenticated in this session
    if not session.get('admin_authenticated'):
        # If they are submitting the password via the gatekeeper form
        if request.method == 'POST' and request.form.get('admin_pw'):
            if request.form.get('admin_pw') == os.getenv("ADMIN_PASSWORD", "JeffP"):
                session['admin_authenticated'] = True
                return redirect(url_for('admin_scoring'))
            else:
                flash("Incorrect Admin Password.")
                return render_template('admin_login.html')

        # Otherwise, show the login gatekeeper
        return render_template('admin_login.html')

    # 2. Normal Admin Logic (This runs once authenticated)
    survivors = Survivor.query.all()
    if request.method == 'POST':
        if 'sync_all' in request.form:
            sync_players()
            flash("Players synced!")
        else:
            wn = int(request.form.get('week_num', 1))
            for s in survivors:
                if request.form.get(f'voted_out_{s.id}'): s.is_out = True
                stat = WeeklyStat(
                    player_id=s.id, week=wn,
                    survived=request.form.get(f'surv_{s.id}') == 'on',
                    immunity=request.form.get(f'imm_{s.id}') == 'on',
                    reward=request.form.get(f'rew_{s.id}') == 'on',
                    advantage=request.form.get(f'adv_{s.id}') == 'on',
                    merge=request.form.get(f'mrg_{s.id}') == 'on',
                    f5=request.form.get(f'f5_{s.id}') == 'on',
                    f3=request.form.get(f'f3_{s.id}') == 'on',
                    winner=request.form.get(f'win_{s.id}') == 'on',
                    crying=request.form.get(f'cry_{s.id}') == 'on',
                    penalty=request.form.get(f'pnl_{s.id}') == 'on',
                    quit=request.form.get(f'quit_{s.id}') == 'on'
                )
                s.points += stat.week_total
                db.session.add(stat)
            db.session.commit()
            flash(f"Scores committed for Week {wn}!")
        return redirect(url_for('admin_scoring'))

    return render_template('admin_scoring.html', survivors=survivors, config=POINTS_CONFIG)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))