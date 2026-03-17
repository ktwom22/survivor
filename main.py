import os, uuid, requests, csv, json, resend, random
from io import StringIO
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, Response, \
    jsonify, make_response, abort
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
    is_locked = db.Column(db.Boolean, default=False)

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


# --- HELPERS ---

def get_weekly_lock_time():
    """Calculates the Wednesday at 8PM EST (Thursday 00:00 UTC) lock for the current week."""
    now = datetime.now(timezone.utc)
    # Wednesday is weekday 2. Calculate offset to find the next/current Wed.
    days_until_wed = (2 - now.weekday()) % 7
    target_wed = now + timedelta(days=days_until_wed)
    # 8PM EST is 00:00 UTC the following morning (Thursday)
    # This logic assumes Eastern is UTC-4/5. 00:00 UTC Thursday is 8PM EST Wednesday.
    lock_time = target_wed.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    return lock_time


def is_locked():
    """True if current time is past the weekly Wednesday 8PM EST lock."""
    return datetime.now(timezone.utc) > get_weekly_lock_time()


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
    if not roster or not roster.cap1_id:
        return None
    c1 = db.session.get(Survivor, roster.cap1_id)
    c2 = db.session.get(Survivor, roster.cap2_id) if roster.cap2_id else None
    c3 = db.session.get(Survivor, roster.cap3_id) if roster.cap3_id else None
    reg_list = []
    if roster.regular_ids:
        ids = [rid.strip() for rid in roster.regular_ids.split(',') if rid.strip()]
        for rid in ids:
            p = db.session.get(Survivor, int(rid))
            if p: reg_list.append(p)
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
        r.cap1_id, r.cap2_id, r.cap3_id = int(picks['cap1']), int(picks['cap2']), int(picks['cap3'])
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
    global_lb = sorted(
        [{'user': r.owner.username, 'score': calculate_roster_score(r, POINTS_CONFIG)} for r in global_rosters if
         r.owner], key=lambda x: x['score'], reverse=True)
    return render_template('home.html', user_leagues=leagues, cast=all_cast, global_top_5=global_lb[:5],
                           total_global_entrants=len(global_rosters), user_in_global=user_in_global,
                           media=get_latest_media(), is_locked=is_locked())


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        hashed_pw = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256')
        new_u = User(username=request.form.get('username'), email=request.form.get('email'), password=hashed_pw)
        try:
            db.session.add(new_u)
            db.session.commit()
            session['user_id'], session['username'] = new_u.id, new_u.username
            process_pending_tribe(new_u.id)
            return redirect(url_for('index'))
        except:
            db.session.rollback()
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
    session.clear()
    return redirect(url_for('index'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(user.email, salt='password-reset-salt')
            reset_url = url_for('reset_with_token', token=token, _external=True)
            try:
                resend.Emails.send({
                    "from": f"Survivor Pool <{SENDER_EMAIL}>",
                    "to": [user.email],
                    "subject": "Reset Your Password",
                    "html": f"Click here to reset: {reset_url}"
                })
                flash("Reset link sent!", "success")
            except:
                flash("Email failed.", "danger")
    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        return redirect(url_for('login'))
    if request.method == 'POST':
        user = User.query.filter_by(email=email).first_or_404()
        user.password = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256')
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('reset_password.html')


@app.route('/create_league', methods=['POST'])
def create_league():
    if 'user_id' not in session: return redirect(url_for('login'))
    return render_template('create_league_config.html', league_name=request.form.get('league_name', 'New League'),
                           default_points=POINTS_CONFIG)


@app.route('/finalize_league', methods=['POST'])
def finalize_league():
    if 'user_id' not in session: return redirect(url_for('login'))
    custom_pts = {k: float(request.form.get(f'val_{k}', 0)) if request.form.get(f'active_{k}') == 'on' else 0 for k in
                  POINTS_CONFIG.keys()}
    code = str(uuid.uuid4())[:6].upper()
    new_l = League(name=request.form.get('league_name'), invite_code=code, settings_json=json.dumps(custom_pts))
    db.session.add(new_l)
    db.session.flush()
    db.session.add(Roster(league_id=new_l.id, user_id=session['user_id']))
    db.session.commit()
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
            db.session.add(Roster(league_id=l.id, user_id=session['user_id']))
            db.session.commit()
        return redirect(url_for('league_dashboard', code=l.invite_code))
    return redirect(url_for('index'))


@app.route('/league/<code>')
def league_dashboard(code):
    if 'user_id' not in session: return redirect(url_for('login'))
    league = League.query.filter_by(invite_code=code).first_or_404()
    l_pts = league.get_points()
    target_username = request.args.get('view_user', session.get('username'))
    all_rosters = Roster.query.filter_by(league_id=league.id).all()
    leaderboard = sorted(
        [{'user': r.owner.username, 'score': calculate_roster_score(r, l_pts)} for r in all_rosters if r.owner],
        key=lambda x: x['score'], reverse=True)

    target_user = User.query.filter_by(username=target_username).first()
    disp_r = Roster.query.filter_by(league_id=league.id, user_id=target_user.id).first() if target_user else None

    # Check if a roster exists
    my_tribe = get_roster_data(disp_r)

    # LOGIC: Show questions ONLY if the roster is NOT empty
    show_questions = False
    if disp_r and disp_r.cap1_id:
        show_questions = True

    return render_template('dashboard.html', league=league, leaderboard=leaderboard, my_tribe=my_tribe,
                           target_username=target_username, show_questions=show_questions,
                           available=Survivor.query.filter_by(is_out=False).all(),
                           league_pts=l_pts, is_locked=is_locked())


@app.route('/draft/<code>', methods=['POST'])
def draft(code):
    if 'user_id' not in session or is_locked(): return redirect(url_for('index'))
    l = League.query.filter_by(invite_code=code).first_or_404()
    r = Roster.query.filter_by(league_id=l.id, user_id=session['user_id']).first()
    if r:
        r.cap1_id, r.cap2_id, r.cap3_id = int(request.form.get('cap1')), int(request.form.get('cap2')), int(
            request.form.get('cap3'))
        r.regular_ids = ",".join(request.form.getlist('regs'))
        db.session.commit()
    return redirect(url_for('league_dashboard', code=code))


@app.route('/global')
def global_leaderboard():
    global_rosters = Roster.query.filter_by(is_global=True).all()
    lb = sorted(
        [{'user': r.owner.username, 'score': calculate_roster_score(r, POINTS_CONFIG)} for r in global_rosters if
         r.owner], key=lambda x: x['score'], reverse=True)
    view_username = request.args.get('view_user', session.get('username') or "Guest")
    target_user = User.query.filter_by(username=view_username).first()
    my_tribe_data = get_roster_data(
        Roster.query.filter_by(user_id=target_user.id, is_global=True).first()) if target_user else None
    return render_template('global_standings.html', full_global_leaderboard=lb, my_tribe=my_tribe_data,
                           display_name=f"{view_username}'s Tribe")


@app.route('/global/draft')
def global_draft_page():
    return render_template('global_draft.html', roster=None, available=Survivor.query.filter_by(is_out=False).all(),
                           config=POINTS_CONFIG, get_roster_data=get_roster_data, is_locked=is_locked())


@app.route('/save_global_draft', methods=['POST'])
def save_global_draft():
    if is_locked(): return redirect(url_for('index'))
    picks = {'cap1': request.form.get('cap1'), 'cap2': request.form.get('cap2'), 'cap3': request.form.get('cap3'),
             'regs': request.form.getlist('regs')}
    if 'user_id' not in session:
        session['pending_tribe'] = picks
        return redirect(url_for('signup'))
    r = Roster.query.filter_by(user_id=session['user_id'], is_global=True).first() or Roster(user_id=session['user_id'],
                                                                                             is_global=True)
    if not r.id: db.session.add(r)
    r.cap1_id, r.cap2_id, r.cap3_id = int(picks['cap1']), int(picks['cap2']), int(picks['cap3'])
    r.regular_ids = ",".join(picks['regs'])
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/admin/scoring', methods=['GET', 'POST'])
def admin_scoring():
    if not session.get('admin_authenticated'):
        if request.method == 'POST' and request.form.get('admin_pw') == os.getenv("ADMIN_PASSWORD", "JeffP"):
            session['admin_authenticated'] = True
            return redirect(url_for('admin_scoring'))
        return render_template('admin_login.html')
    if request.method == 'POST' and request.is_json:
        data = request.json
        stat = WeeklyStat.query.filter_by(player_id=data['player_id'], week=data['week']).first() or WeeklyStat(
            player_id=data['player_id'], week=data['week'])
        if not stat.id: db.session.add(stat)
        if hasattr(stat, data['category']):
            setattr(stat, data['category'], data['state'])
            db.session.commit()
            p = db.session.get(Survivor, data['player_id'])
            p.points = sum(
                s.calculate_for_league(POINTS_CONFIG) for s in WeeklyStat.query.filter_by(player_id=p.id).all())
            db.session.commit()
            return jsonify({"success": True, "new_total": round(p.points, 1)})
    survivors = Survivor.query.all()
    week = int(request.args.get('week', 1))
    current_stats = {s.player_id: s for s in WeeklyStat.query.filter_by(week=week).all()}
    return render_template('admin_scoring.html', survivors=survivors, config=POINTS_CONFIG, week=week,
                           current_stats=current_stats)


@app.route('/trends')
def draft_trends():
    rosters = Roster.query.filter(Roster.cap1_id.isnot(None)).all()
    total = len(rosters)
    stats = []
    if total > 0:
        for s in Survivor.query.all():
            count = sum(1 for r in rosters if r.cap1_id == s.id or r.cap2_id == s.id or r.cap3_id == s.id or (
                        r.regular_ids and str(s.id) in r.regular_ids.split(',')))
            if count > 0: stats.append(
                {'name': s.name, 'slug': s.slug, 'image': s.image_url, 'total_pct': round((count / total) * 100, 1)})
    return render_template('trends.html', stats=sorted(stats, key=lambda x: x['total_pct'], reverse=True),
                           total_users=total)


@app.route('/player/<string:slug>')
def player_profile(slug):
    p = Survivor.query.filter((Survivor.slug == slug) | (Survivor.id == slug)).first_or_404()
    totals = {'surv': sum(1 for s in p.stats if s.survived), 'imm': sum(1 for s in p.stats if s.immunity),
              'score': round(p.points, 1)}
    return render_template('player_profile.html', p=p, totals=totals)


@app.route('/robots.txt')
def robots(): return send_from_directory(app.static_folder, 'robots.txt')


@app.route('/sitemap.xml')
def sitemap():
    pages = [{"loc": url_for('index', _external=True), "lastmod": datetime.now().strftime('%Y-%m-%d')}]
    for p in Survivor.query.all(): pages.append({"loc": url_for('player_profile', slug=p.slug or p.id, _external=True),
                                                 "lastmod": datetime.now().strftime('%Y-%m-%d')})
    return Response(render_template('sitemap_template.xml', pages=pages), mimetype='application/xml')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        try:
            db.session.execute(text("ALTER TABLE survivor ADD COLUMN slug VARCHAR(100) UNIQUE"))
        except:
            db.session.rollback()
        sync_players()
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8080)))