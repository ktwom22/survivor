import os, uuid, requests, csv, json, resend
from io import StringIO
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, Response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer

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

# --- GLOBAL DEFAULTS ---
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
            if not p:
                p = Survivor(name=name, points=0.0) # PATCH: Ensure 0.0 points for new players
                db.session.add(p)
            p.image_url = row.get('Image Link', '').strip()
            p.season = row.get('What Season?', '').strip()
            p.details = row.get('Details', '').strip()
            if p.points is None: p.points = 0.0 # PATCH: Repair existing Null points
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

# --- ROUTES ---

@app.route('/')
def index(): # FIXED: Changed from 'home' to 'index' to resolve BuildError
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
        if r.owner:
            global_lb.append({'user': r.owner.username, 'score': calculate_roster_score(r, POINTS_CONFIG)})

    global_top_5 = sorted(global_lb, key=lambda x: x['score'], reverse=True)[:5]
    return render_template('home.html', user_leagues=leagues, cast=all_cast, global_top_5=global_top_5,
                           total_global_entrants=len(global_rosters), user_in_global=user_in_global)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        hashed_pw = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256')
        new_u = User(username=request.form.get('username'), email=request.form.get('email'), password=hashed_pw)
        try:
            db.session.add(new_u); db.session.commit()
            session['user_id'], session['username'] = new_u.id, new_u.username
            return redirect(url_for('index'))
        except:
            db.session.rollback(); flash("Username/Email already exists.")
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = User.query.filter((User.email == request.form.get('email')) | (User.username == request.form.get('email'))).first()
        if u and check_password_hash(u.password, request.form.get('password')):
            session['user_id'], session['username'] = u.id, u.username
            return redirect(url_for('index'))
        flash("Invalid credentials.", "danger")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear(); return redirect(url_for('index'))

# --- PASSWORD RECOVERY ---

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
                    "html": f"""
                        <div style="background:#000; color:#fff; padding:20px; border:4px solid #FFD700; font-family:sans-serif;">
                            <h2 style="color:#FFD700;">PASSWORD RESET REQUEST</h2>
                            <p>Click the button below to secure your tribe's access:</p>
                            <a href="{reset_url}" style="background:#FFD700; color:#000; padding:12px 25px; text-decoration:none; font-weight:bold; display:inline-block; margin:20px 0;">RESET PASSWORD</a>
                        </div>
                    """
                })
                flash("Reset link sent! Check your inbox.", "success")
            except Exception:
                flash("Email failed to send.", "danger")
        else:
            flash("If registered, a link has been sent.", "info")
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash("Invalid or expired link.", "danger")
        return redirect(url_for('login'))
    if request.method == 'POST':
        user = User.query.filter_by(email=email).first_or_404()
        user.password = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256')
        db.session.commit()
        flash("Password updated!", "success")
        return redirect(url_for('login'))
    return render_template('reset_password.html')

# --- LEAGUE ROUTES ---

@app.route('/create_league', methods=['POST'])
def create_league():
    if 'user_id' not in session: return redirect(url_for('login'))
    return render_template('create_league_config.html', league_name=request.form.get('league_name', 'New League'), default_points=POINTS_CONFIG)


@app.route('/finalize_league', methods=['POST'])
def finalize_league():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # SAFETY CHECK: Ensure the user actually exists in the DB
    current_user = db.session.get(User, session['user_id'])
    if not current_user:
        session.clear()
        flash("User not found. Please register again.", "danger")
        return redirect(url_for('signup'))

    custom_pts = {key: float(request.form.get(f'val_{key}', 0)) if request.form.get(f'active_{key}') == 'on' else 0 for
                  key in POINTS_CONFIG.keys()}
    code = str(uuid.uuid4())[:6].upper()

    new_l = League(name=request.form.get('league_name'), invite_code=code, settings_json=json.dumps(custom_pts))
    db.session.add(new_l)
    db.session.flush()  # This generates the new_l.id

    # Now creating the roster with a verified user_id
    db.session.add(Roster(league_id=new_l.id, user_id=current_user.id))

    try:
        db.session.commit()
        return redirect(url_for('league_success', code=code))
    except Exception as e:
        db.session.rollback()
        flash("Database error. Try again.", "danger")
        return redirect(url_for('index'))


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
    flash("League not found.", "danger"); return redirect(url_for('index'))

@app.route('/league/<code>')
def league_dashboard(code):
    if 'user_id' not in session: return redirect(url_for('login'))
    league = League.query.filter_by(invite_code=code).first_or_404()
    l_pts = league.get_points()
    target_username = request.args.get('view_user', session.get('username'))
    all_rosters = Roster.query.filter_by(league_id=league.id).all()
    leaderboard = sorted([{'user': r.owner.username, 'score': calculate_roster_score(r, l_pts)} for r in all_rosters if r.owner], key=lambda x: x['score'], reverse=True)
    target_user = User.query.filter_by(username=target_username).first()
    disp_r = Roster.query.filter_by(league_id=league.id, user_id=target_user.id).first() if target_user else None
    return render_template('dashboard.html', league=league, leaderboard=leaderboard, my_tribe=get_roster_data(disp_r), target_username=target_username, available=Survivor.query.filter_by(is_out=False).all(), league_pts=l_pts)

@app.route('/draft/<code>', methods=['POST'])
def draft(code):
    if 'user_id' not in session: return redirect(url_for('login'))
    l = League.query.filter_by(invite_code=code).first_or_404()
    r = Roster.query.filter_by(league_id=l.id, user_id=session['user_id']).first()
    if r:
        c1, c2, c3 = request.form.get('cap1'), request.form.get('cap2'), request.form.get('cap3')
        regs = request.form.getlist('regs')
        r.cap1_id, r.cap2_id, r.cap3_id = int(c1), int(c2), int(c3)
        r.regular_ids = ",".join(regs)
        db.session.commit(); flash("Draft saved!", "success")
    return redirect(url_for('league_dashboard', code=code))

# --- GLOBAL STANDINGS ---

@app.route('/join-global', methods=['POST'])
def join_global():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    r = Roster.query.filter_by(user_id=session['user_id'], is_global=True).first()
    if not r:
        r = Roster(user_id=session['user_id'], is_global=True)
        db.session.add(r); db.session.commit()
        flash("Welcome to the Global Season! Time to draft your tribe.", "success")
    return redirect(url_for('global_draft_page'))


@app.route('/global-leaderboard')
def global_leaderboard():
    if 'user_id' not in session or 'username' not in session:
        flash("Please log in to view the Global Standings.", "info")
        return redirect(url_for('login'))

    global_rosters = Roster.query.filter_by(is_global=True).all()
    lb = sorted(
        [{'user': r.owner.username, 'score': calculate_roster_score(r, POINTS_CONFIG)} for r in global_rosters if
         r.owner], key=lambda x: x['score'], reverse=True)

    view_username = request.args.get('view_user', session['username'])

    target_tribe_data = None
    display_name = "Global Entry"

    target_user = User.query.filter_by(username=view_username).first()
    if target_user:
        display_roster = Roster.query.filter_by(user_id=target_user.id, is_global=True).first()
        if display_roster:
            target_tribe_data = get_roster_data(display_roster)
            display_name = f"{target_user.username}'s Tribe"

    return render_template('global_standings.html',
                           full_global_leaderboard=lb,
                           total_global_entrants=len(lb),
                           my_tribe=target_tribe_data,
                           display_name=display_name)

@app.route('/global/draft')
def global_draft_page():
    if 'user_id' not in session: return redirect(url_for('login'))
    roster = Roster.query.filter_by(user_id=session['user_id'], is_global=True).first()
    available = Survivor.query.filter_by(is_out=False).all()
    return render_template('global_draft.html', roster=roster, available=available, config=POINTS_CONFIG, get_roster_data=get_roster_data)


@app.route('/save_global_draft', methods=['POST'])
def save_global_draft():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_exists = db.session.get(User, session['user_id'])
    if not user_exists:
        session.clear()
        flash("Session expired or user not found. Please log in again.", "danger")
        return redirect(url_for('login'))

    r = Roster.query.filter_by(user_id=session['user_id'], is_global=True).first() or Roster(user_id=session['user_id'], is_global=True)
    if not r.id:
        db.session.add(r)

    r.cap1_id = int(request.form.get('cap1'))
    r.cap2_id = int(request.form.get('cap2'))
    r.cap3_id = int(request.form.get('cap3'))
    r.regular_ids = ",".join(request.form.getlist('regs'))

    try:
        db.session.commit()
        flash("Global Tribe saved!", "success")
    except Exception as e:
        db.session.rollback()
        flash("Error saving draft. Please try again.", "danger")

    return redirect(url_for('index'))

# --- PROFILES & ADMIN ---

@app.route('/player/<int:player_id>')
def player_profile(player_id):
    p = Survivor.query.get_or_404(player_id)
    totals = {'surv': sum(1 for s in p.stats if s.survived), 'imm': sum(1 for s in p.stats if s.immunity), 'score': round(p.points, 1)}
    return render_template('player_profile.html', p=p, totals=totals)

@app.route('/admin/scoring', methods=['GET', 'POST'])
def admin_scoring():
    if not session.get('admin_authenticated'):
        if request.method == 'POST' and request.form.get('admin_pw') == os.getenv("ADMIN_PASSWORD", "JeffP"):
            session['admin_authenticated'] = True
            return redirect(url_for('admin_scoring'))
        return render_template('admin_login.html')
    survivors = Survivor.query.all()
    if request.method == 'POST':
        if 'sync_all' in request.form: sync_players()
        else:
            wn = int(request.form.get('week_num', 1))
            for s in survivors:
                if request.form.get(f'voted_out_{s.id}'): s.is_out = True
                stat = WeeklyStat(
                    player_id=s.id,
                    week=wn,
                    survived=request.form.get(f'surv_{s.id}') == 'on',
                    immunity=request.form.get(f'imm_{s.id}') == 'on',
                    reward=request.form.get(f'rew_{s.id}') == 'on',
                    advantage=request.form.get(f'adv_{s.id}') == 'on',
                    journey=request.form.get(f'jour_{s.id}') == 'on',
                    in_pocket=request.form.get(f'pocket_{s.id}') == 'on',
                    crying=request.form.get(f'cry_{s.id}') == 'on'
                )
                if s.points is None: s.points = 0.0 # PATCH: Safety against None points
                s.points += stat.calculate_for_league(POINTS_CONFIG)
                db.session.add(stat)
            db.session.commit(); flash(f"Week {wn} results published!")
        return redirect(url_for('admin_scoring'))
    return render_template('admin_login.html' if not session.get('admin_authenticated') else 'admin_scoring.html', survivors=survivors, config=POINTS_CONFIG)


@app.route('/robots.txt')
def robots():
    return send_from_directory(app.static_folder, 'robots.txt')


@app.route('/sitemap.xml', methods=['GET'])
def sitemap():
    pages = []
    main_functions = ['index', 'global_leaderboard', 'login']

    for func in main_functions:
        try:
            pages.append({
                "loc": url_for(func, _external=True),
                "lastmod": "2026-02-20",
                "priority": "1.0" if func == 'index' else "0.8"
            })
        except Exception as e:
            print(f"Skipping {func}: {e}")

    try:
        players = Survivor.query.all()
        for p in players:
            pages.append({
                "loc": url_for('player_profile', player_id=p.id, _external=True),
                "lastmod": "2026-02-20",
                "priority": "0.7"
            })
    except Exception as e:
        print(f"Error loading players for sitemap: {e}")

    sitemap_xml = render_template('sitemap_template.xml', pages=pages)
    return Response(sitemap_xml, mimetype='application/xml')


@app.route('/trends')
def draft_trends():
    submitted_rosters = Roster.query.filter(Roster.cap1_id.isnot(None)).all()
    total_count = len(submitted_rosters)

    if total_count == 0:
        return render_template('trends.html', stats=[], total_users=0,
                               error="No completed drafts found yet. Start drafting to see trends!")

    all_survivors = Survivor.query.all()
    stats_list = []

    for s in all_survivors:
        gold_picks = sum(1 for r in submitted_rosters if r.cap1_id == s.id)
        silver_picks = sum(1 for r in submitted_rosters if r.cap2_id == s.id)
        bronze_picks = sum(1 for r in submitted_rosters if r.cap3_id == s.id)
        reg_picks = sum(1 for r in submitted_rosters if r.regular_ids and str(s.id) in r.regular_ids.split(','))
        total_picks = gold_picks + silver_picks + bronze_picks + reg_picks

        if total_picks > 0:
            stats_list.append({
                'name': s.name,
                'image': s.image_url,
                'total_pct': round((total_picks / total_count) * 100, 1),
                'captain_pct': round(((gold_picks + silver_picks + bronze_picks) / total_count) * 100, 1),
                'gold_pct': round((gold_picks / total_count) * 100, 1),
                'count': total_picks
            })

    stats_list = sorted(stats_list, key=lambda x: x['total_pct'], reverse=True)
    return render_template('trends.html', stats=stats_list, total_users=total_count)


@app.route('/nuke_and_pave')
def nuke_and_pave():
    db.drop_all(); db.create_all(); sync_players()
    return "Database reset! <a href='/'>Go Home</a>"

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8080)))