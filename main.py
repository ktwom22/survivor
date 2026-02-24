import os, uuid, requests, csv, json, resend, random
from io import StringIO
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, Response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import text

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "survivor_2026_pro_key")

# --- AUTH & EMAIL CONFIG ---
resend.api_key = os.getenv("RESEND_API_KEY")
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "onboarding@resend.dev")
serializer = URLSafeTimedSerializer(app.secret_key)

# --- DATABASE CONFIG ---
db_url = os.getenv("DATABASE_URL")
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url or 'sqlite:///survivor_v7.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- GLOBAL DEFAULTS & LOCKS ---
POINTS_CONFIG = {
    "survive_episode": 2.0, "win_immunity": 5.0, "win_reward": 2.0,
    "found_advantage": 4.0, "made_merge": 5.0, "final_five": 8.0,
    "final_three": 12.0, "winner": 20.0, "confessional_cry": 2.0,
    "in_pocket": -5.0, "journey": 3.0, "quit_game": -25.0
}

# Survivor 50 Premiere Lock: Feb 25, 2026 8PM EST = Feb 26, 2026 1AM UTC
LOCK_DATETIME = datetime(2026, 2, 26, 1, 0, tzinfo=timezone.utc)


# --- MODELS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    rosters = db.relationship('Roster', backref='owner', cascade="all, delete-orphan", lazy=True)
    bracket_picks = db.relationship('BracketPick', backref='user', cascade="all, delete-orphan", lazy=True)


class Survivor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    slug = db.Column(db.String(100), unique=True, nullable=True)
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
    survived = db.Column(db.Boolean, default=False)
    immunity = db.Column(db.Boolean, default=False)
    reward = db.Column(db.Boolean, default=False)
    advantage = db.Column(db.Boolean, default=False)
    journey = db.Column(db.Boolean, default=False)
    in_pocket = db.Column(db.Boolean, default=False)
    merge = db.Column(db.Boolean, default=False)
    f5 = db.Column(db.Boolean, default=False)
    f3 = db.Column(db.Boolean, default=False)
    winner = db.Column(db.Boolean, default=False)
    crying = db.Column(db.Boolean, default=False)
    quit = db.Column(db.Boolean, default=False)

    def calculate_for_league(self, league_pts):
        t = 0
        mapping = {
            "survive_episode": self.survived, "win_immunity": self.immunity,
            "win_reward": self.reward, "found_advantage": self.advantage,
            "went_on_journey": self.journey, "in_pocket": self.in_pocket,
            "made_merge": self.merge, "final_five": self.f5,
            "final_three": self.f3, "winner": self.winner,
            "confessional_cry": self.crying, "quit_game": self.quit
        }
        for key, active in mapping.items():
            if active: t += league_pts.get(key, 0)
        return t


class League(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    invite_code = db.Column(db.String(10), unique=True)
    settings_json = db.Column(db.Text, nullable=True)
    bracket_picks = db.relationship('BracketPick', backref='league', lazy=True)

    def get_points(self):
        return json.loads(self.settings_json) if self.settings_json else POINTS_CONFIG


class Roster(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    league_id = db.Column(db.Integer, db.ForeignKey('league.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    is_global = db.Column(db.Boolean, default=False)
    cap1_id = db.Column(db.Integer)
    cap2_id = db.Column(db.Integer)
    cap3_id = db.Column(db.Integer)
    regular_ids = db.Column(db.String(200))


class Match(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    match_number = db.Column(db.Integer, unique=True)
    stage = db.Column(db.String(50))  # e.g., 'Round of 32', 'Quarter-final'
    team_a_id = db.Column(db.Integer, db.ForeignKey('survivor.id'), nullable=True)
    team_b_id = db.Column(db.Integer, db.ForeignKey('survivor.id'), nullable=True)
    winner_id = db.Column(db.Integer, db.ForeignKey('survivor.id'), nullable=True)
    next_match_id = db.Column(db.Integer, nullable=True)


class BracketPick(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    league_id = db.Column(db.Integer, db.ForeignKey('league.id'), nullable=True)
    match_id = db.Column(db.Integer, db.ForeignKey('match.id'))
    predicted_winner_id = db.Column(db.Integer, db.ForeignKey('survivor.id'))


# --- HELPERS ---

def is_locked():
    """Checks if the current time is past the lock date."""
    return datetime.now(timezone.utc) > LOCK_DATETIME


def get_latest_media():
    return [
        {"title": "Survivor 50 Pre-Season Cast Analysis", "channel": "Idoled Out", "id": "GeFrVmNvu64",
         "date": "Feb 15, 2026"},
        {"title": "Reacting to the Survivor 50 Tribes", "channel": "RHAP", "id": "F5H6hyR7oWg", "date": "Jan 28, 2026"},
        {"title": "The Story of Every Survivor 50 Player", "channel": "Idoled Out", "id": "iyKkNmo6-6c",
         "date": "Jan 11, 2026"}
    ]


def sync_players():
    url = "https://docs.google.com/spreadsheets/d/e/2PACX-1vQoYLaaQ7OnWbEiHpJo27v0PUzp6r_ufLCHgpYB5kdHluNOgQilvIsZNU_pp78nda4Jd5Vislg1VYbO/pub?gid=0&single=true&output=csv"
    try:
        r = requests.get(url)
        r.encoding = 'utf-8'
        reader = csv.DictReader(StringIO(r.text))
        for row in reader:
            name = row.get('Name', '').strip()
            if not name: continue
            p = Survivor.query.filter_by(name=name).first()
            slug_name = name.lower().replace(" ", "_").replace("'", "").replace("-", "_")
            if not p:
                p = Survivor(name=name, points=0.0, slug=slug_name)
                db.session.add(p)
            else:
                if not p.slug: p.slug = slug_name
            p.image_url = row.get('Image Link', '').strip()
            p.season = row.get('What Season?', '').strip()
            p.details = row.get('Details', '').strip()
            if p.points is None: p.points = 0.0
        db.session.commit()
    except Exception as e:
        print(f"Sync error: {e}")


def get_roster_data(roster):
    if not roster: return None
    c1 = db.session.get(Survivor, roster.cap1_id) if roster.cap1_id else None
    c2 = db.session.get(Survivor, roster.cap2_id) if roster.cap2_id else None
    c3 = db.session.get(Survivor, roster.cap3_id) if roster.cap3_id else None
    reg_list = []
    if roster.regular_ids:
        for rid in roster.regular_ids.split(','):
            if rid.strip():
                player = db.session.get(Survivor, int(rid))
                if player: reg_list.append(player)
    return {"cap1": c1, "cap2": c2, "cap3": c3, "regs": reg_list}


def calculate_roster_score(roster, pts_config):
    data = get_roster_data(roster)
    if not data: return 0.0
    score = 0.0
    if data['cap1']: score += sum(s.calculate_for_league(pts_config) for s in data['cap1'].stats) * 2.0
    if data['cap2']: score += sum(s.calculate_for_league(pts_config) for s in data['cap2'].stats) * 1.5
    if data['cap3']: score += sum(s.calculate_for_league(pts_config) for s in data['cap3'].stats) * 1.25
    for p in data['regs']:
        score += sum(s.calculate_for_league(pts_config) for s in p.stats)
    return round(score, 1)


def process_pending_tribe(user_id):
    if is_locked():
        session.pop('pending_tribe', None)
        return False
    if 'pending_tribe' in session:
        picks = session.pop('pending_tribe')
        r = Roster.query.filter_by(user_id=user_id, is_global=True).first() or Roster(user_id=user_id, is_global=True)
        if not r.id: db.session.add(r)
        r.cap1_id = int(picks['cap1']);
        r.cap2_id = int(picks['cap2']);
        r.cap3_id = int(picks['cap3'])
        r.regular_ids = ",".join(picks['regs'])
        db.session.commit()
        return True
    return False


# --- ROUTES ---

@app.route('/')
def index():
    all_cast = Survivor.query.all()
    leagues = []
    user_in_global = False
    if 'user_id' in session:
        my_rosters = Roster.query.filter_by(user_id=session['user_id']).all()
        leagues = League.query.filter(League.id.in_([r.league_id for r in my_rosters if r.league_id])).all()
        user_in_global = any(r.is_global for r in my_rosters)
    global_rosters = Roster.query.filter_by(is_global=True).all()
    global_lb = []
    for r in global_rosters:
        if r.owner: global_lb.append({'user': r.owner.username, 'score': calculate_roster_score(r, POINTS_CONFIG)})
    global_top_5 = sorted(global_lb, key=lambda x: x['score'], reverse=True)[:5]
    return render_template('home.html', user_leagues=leagues, cast=all_cast, global_top_5=global_top_5,
                           total_global_entrants=len(global_rosters), user_in_global=user_in_global,
                           media=get_latest_media(), is_locked=is_locked())


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        hashed_pw = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256')
        new_u = User(username=request.form.get('username'), email=request.form.get('email'), password=hashed_pw)
        try:
            db.session.add(new_u);
            db.session.commit()
            session['user_id'], session['username'] = new_u.id, new_u.username
            process_pending_tribe(new_u.id)
            return redirect(url_for('index'))
        except:
            db.session.rollback();
            flash("Username/Email already exists.")
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = User.query.filter(
            (User.email == request.form.get('email')) | (User.username == request.form.get('email'))).first()
        if u and check_password_hash(u.password, request.form.get('password')):
            session['user_id'], session['username'] = u.id, u.username
            process_pending_tribe(u.id)
            return redirect(url_for('index'))
        flash("Invalid credentials.", "danger")
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear();
    return redirect(url_for('index'))


@app.route('/create_league', methods=['POST'])
def create_league():
    if 'user_id' not in session: return redirect(url_for('login'))
    return render_template('create_league_config.html', league_name=request.form.get('league_name', 'New League'),
                           default_points=POINTS_CONFIG)


@app.route('/finalize_league', methods=['POST'])
def finalize_league():
    if 'user_id' not in session: return redirect(url_for('login'))
    current_user = db.session.get(User, session['user_id'])
    custom_pts = {key: float(request.form.get(f'val_{key}', 0)) if request.form.get(f'active_{key}') == 'on' else 0 for
                  key in POINTS_CONFIG.keys()}
    code = str(uuid.uuid4())[:6].upper()
    new_l = League(name=request.form.get('league_name'), invite_code=code, settings_json=json.dumps(custom_pts))
    db.session.add(new_l);
    db.session.flush()
    db.session.add(Roster(league_id=new_l.id, user_id=current_user.id))
    db.session.commit();
    return redirect(url_for('league_success', code=code))


@app.route('/league-created/<code>')
def league_success(code):
    return render_template('league_success.html', league=League.query.filter_by(invite_code=code).first_or_404())


@app.route('/join_league', methods=['POST'])
def join_league():
    if 'user_id' not in session: return redirect(url_for('login'))
    l = League.query.filter_by(invite_code=request.form.get('invite_code', '').upper().strip()).first()
    if l:
        if not Roster.query.filter_by(league_id=l.id, user_id=session['user_id']).first():
            db.session.add(Roster(league_id=l.id, user_id=session['user_id']));
            db.session.commit()
        return redirect(url_for('league_dashboard', code=l.invite_code))
    flash("League not found.", "danger");
    return redirect(url_for('index'))


@app.route('/league/<code>')
def league_dashboard(code):
    if 'user_id' not in session: return redirect(url_for('login'))
    league = League.query.filter_by(invite_code=code).first_or_404()
    l_pts = league.get_points()
    all_rosters = Roster.query.filter_by(league_id=league.id).all()
    leaderboard = sorted(
        [{'user': r.owner.username, 'score': calculate_roster_score(r, l_pts)} for r in all_rosters if r.owner],
        key=lambda x: x['score'], reverse=True)
    target_user = User.query.filter_by(username=request.args.get('view_user', session.get('username'))).first()
    disp_r = Roster.query.filter_by(league_id=league.id, user_id=target_user.id).first() if target_user else None
    return render_template('dashboard.html', league=league, leaderboard=leaderboard, my_tribe=get_roster_data(disp_r),
                           available=Survivor.query.filter_by(is_out=False).all(), league_pts=l_pts,
                           is_locked=is_locked())


@app.route('/draft/<code>', methods=['POST'])
def draft(code):
    if 'user_id' not in session: return redirect(url_for('login'))
    if is_locked(): flash("Rosters are locked!", "danger"); return redirect(url_for('league_dashboard', code=code))
    l = League.query.filter_by(invite_code=code).first_or_404()
    r = Roster.query.filter_by(league_id=l.id, user_id=session['user_id']).first()
    if r:
        r.cap1_id = int(request.form.get('cap1'));
        r.cap2_id = int(request.form.get('cap2'));
        r.cap3_id = int(request.form.get('cap3'))
        r.regular_ids = ",".join(request.form.getlist('regs'));
        db.session.commit();
        flash("Draft saved!", "success")
    return redirect(url_for('league_dashboard', code=code))


# --- BRACKET ROUTES ---

@app.route('/league/<code>/bracket')
def view_bracket(code):
    if 'user_id' not in session: return redirect(url_for('login'))
    league = League.query.filter_by(invite_code=code).first() if code != "global" else None
    l_id = league.id if league else None

    matches = Match.query.order_by(Match.match_number).all()
    user_picks = BracketPick.query.filter_by(user_id=session['user_id'], league_id=l_id).all()
    pick_dict = {p.match_id: p.predicted_winner_id for p in user_picks}

    return render_template('bracket.html', league=league, matches=matches, picks=pick_dict,
                           available=Survivor.query.all(), is_locked=is_locked())


@app.route('/league/<code>/save_bracket', methods=['POST'])
def save_bracket(code):
    if is_locked(): flash("Bracket is locked!", "danger"); return redirect(url_for('index'))
    league = League.query.filter_by(invite_code=code).first() if code != "global" else None
    l_id = league.id if league else None

    for key, value in request.form.items():
        if key.startswith('match_'):
            m_id = int(key.replace('match_', ''))
            pick = BracketPick.query.filter_by(user_id=session['user_id'], league_id=l_id, match_id=m_id).first()
            if not pick:
                pick = BracketPick(user_id=session['user_id'], league_id=l_id, match_id=m_id)
                db.session.add(pick)
            pick.predicted_winner_id = int(value)

    db.session.commit();
    flash("Bracket picks saved!", "success")
    return redirect(url_for('view_bracket', code=code))


@app.route('/save_global_draft', methods=['POST'])
def save_global_draft():
    if is_locked(): flash("Global drafting is closed!", "danger"); return redirect(url_for('index'))
    picks = {'cap1': request.form.get('cap1'), 'cap2': request.form.get('cap2'), 'cap3': request.form.get('cap3'),
             'regs': request.form.getlist('regs')}
    if 'user_id' not in session:
        session['pending_tribe'] = picks;
        flash("Tribe captured! Signup to save.", "info");
        return redirect(url_for('signup'))
    r = Roster.query.filter_by(user_id=session['user_id'], is_global=True).first() or Roster(user_id=session['user_id'],
                                                                                             is_global=True)
    if not r.id: db.session.add(r)
    r.cap1_id = int(picks['cap1']);
    r.cap2_id = int(picks['cap2']);
    r.cap3_id = int(picks['cap3']);
    r.regular_ids = ",".join(picks['regs'])
    db.session.commit();
    flash("Global Tribe saved!", "success");
    return redirect(url_for('index'))


@app.route('/admin/scoring', methods=['GET', 'POST'])
def admin_scoring():
    if not session.get('admin_authenticated'):
        if request.method == 'POST' and request.form.get('admin_pw') == os.getenv("ADMIN_PASSWORD", "JeffP"):
            session['admin_authenticated'] = True;
            return redirect(url_for('admin_scoring'))
        return render_template('admin_login.html')
    survivors = Survivor.query.all()
    if request.method == 'POST':
        if 'sync_all' in request.form:
            sync_players()
        else:
            wn = int(request.form.get('week_num', 1))
            for s in survivors:
                if request.form.get(f'voted_out_{s.id}'): s.is_out = True
                stat = WeeklyStat(player_id=s.id, week=wn, survived=request.form.get(f'surv_{s.id}') == 'on',
                                  immunity=request.form.get(f'imm_{s.id}') == 'on',
                                  crying=request.form.get(f'cry_{s.id}') == 'on')
                if s.points is None: s.points = 0.0
                s.points += stat.calculate_for_league(POINTS_CONFIG);
                db.session.add(stat)
            db.session.commit();
            flash(f"Week {wn} published!")
        return redirect(url_for('admin_scoring'))
    return render_template('admin_scoring.html', survivors=survivors, config=POINTS_CONFIG)


@app.route('/nuke_and_pave')
def nuke_and_pave():
    db.drop_all();
    db.create_all();
    sync_players();
    return "Reset! <a href='/'>Home</a>"


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8080)))