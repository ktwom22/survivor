import os, uuid, requests, csv, json, resend, random
from io import StringIO
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, Response, \
    jsonify
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

# STATUS: UPDATED GRACE PERIOD
# Set to 5AM UTC (Midnight EST) to allow for premiere-night roster corrections.
LOCK_DATETIME = datetime(2026, 2, 26, 5, 0, tzinfo=timezone.utc)


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

def is_locked():
    """Checks if the current time is past the Survivor 50 premiere lock."""
    return datetime.now(timezone.utc) > LOCK_DATETIME


def get_latest_media():
    """Returns a list of recent Survivor YouTube videos for the homepage."""
    return [
        {
            "title": "Survivor 50 Pre-Season Cast Analysis",
            "channel": "Idoled Out",
            "id": "GeFrVmNvu64",
            "date": "Feb 15, 2026"
        },
        {
            "title": "Reacting to the Survivor 50 Tribes",
            "channel": "RHAP",
            "id": "F5H6hyR7oWg",
            "date": "Jan 28, 2026"
        },
        {
            "title": "The Story of Every Survivor 50 Player",
            "channel": "Idoled Out",
            "id": "iyKkNmo6-6c",
            "date": "Jan 11, 2026"
        }
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
                if not p.slug:
                    p.slug = slug_name
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
        # Split and filter out empty strings to prevent errors from trailing commas
        ids = [rid.strip() for rid in roster.regular_ids.split(',') if rid.strip()]
        for rid in ids:
            try:
                player = db.session.get(Survivor, int(rid))
                if player: reg_list.append(player)
            except ValueError:
                continue
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
    """Helper to save a draft after registration/login"""
    if is_locked():
        session.pop('pending_tribe', None)
        return False

    if 'pending_tribe' in session:
        picks = session.pop('pending_tribe')
        r = Roster.query.filter_by(user_id=user_id, is_global=True).first() or Roster(user_id=user_id, is_global=True)
        if not r.id:
            db.session.add(r)
        r.cap1_id = int(picks['cap1'])
        r.cap2_id = int(picks['cap2'])
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
        if r.owner:
            global_lb.append({'user': r.owner.username, 'score': calculate_roster_score(r, POINTS_CONFIG)})

    global_top_5 = sorted(global_lb, key=lambda x: x['score'], reverse=True)[:5]
    media_items = get_latest_media()

    return render_template('home.html', user_leagues=leagues, cast=all_cast, global_top_5=global_top_5,
                           total_global_entrants=len(global_rosters), user_in_global=user_in_global,
                           media=media_items, is_locked=is_locked())


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        hashed_pw = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256')
        new_u = User(username=request.form.get('username'), email=request.form.get('email'), password=hashed_pw)
        try:
            db.session.add(new_u)
            db.session.commit()
            session['user_id'], session['username'] = new_u.id, new_u.username

            # Check for guest draft
            if process_pending_tribe(new_u.id):
                flash("Welcome! Your tribe has been locked in.", "success")

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

            # Check for guest draft
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


@app.route('/create_league', methods=['POST'])
def create_league():
    if 'user_id' not in session: return redirect(url_for('login'))
    return render_template('create_league_config.html', league_name=request.form.get('league_name', 'New League'),
                           default_points=POINTS_CONFIG)


@app.route('/finalize_league', methods=['POST'])
def finalize_league():
    if 'user_id' not in session:
        return redirect(url_for('login'))
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
    db.session.flush()
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
    flash("League not found.", "danger")
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
    return render_template('dashboard.html', league=league, leaderboard=leaderboard, my_tribe=get_roster_data(disp_r),
                           target_username=target_username, available=Survivor.query.filter_by(is_out=False).all(),
                           league_pts=l_pts, get_roster_data=get_roster_data, is_locked=is_locked())


@app.route('/draft/<code>', methods=['POST'])
def draft(code):
    if 'user_id' not in session: return redirect(url_for('login'))

    if is_locked():
        flash("The tribe has spoken! Rosters are locked for the premiere.", "danger")
        return redirect(url_for('league_dashboard', code=code))

    l = League.query.filter_by(invite_code=code).first_or_404()
    r = Roster.query.filter_by(league_id=l.id, user_id=session['user_id']).first()
    if r:
        c1, c2, c3 = request.form.get('cap1'), request.form.get('cap2'), request.form.get('cap3')
        regs = request.form.getlist('regs')
        r.cap1_id, r.cap2_id, r.cap3_id = int(c1), int(c2), int(c3)
        r.regular_ids = ",".join(regs)
        db.session.commit()
        flash("Draft saved!", "success")
    return redirect(url_for('league_dashboard', code=code))


@app.route('/join-global', methods=['POST'])
def join_global():
    # If not logged in, just send to draft as a guest
    if 'user_id' not in session:
        return redirect(url_for('global_draft_page'))

    r = Roster.query.filter_by(user_id=session['user_id'], is_global=True).first()
    if not r:
        r = Roster(user_id=session['user_id'], is_global=True)
        db.session.add(r)
        db.session.commit()
        flash("Welcome to the Global Season! Time to draft your tribe.", "success")
    return redirect(url_for('global_draft_page'))


@app.route('/global')
@app.route('/global-leaderboard')
def global_leaderboard():
    global_rosters = Roster.query.filter_by(is_global=True).all()
    lb = []
    for r in global_rosters:
        if r.owner:
            lb.append({
                'user': r.owner.username,
                'score': calculate_roster_score(r, POINTS_CONFIG)
            })

    lb = sorted(lb, key=lambda x: x['score'], reverse=True)
    view_username = request.args.get('view_user', session.get('username') or "Guest")
    target_user = User.query.filter_by(username=view_username).first()

    my_tribe_data = None
    display_name = "Global Contest"

    if target_user:
        target_roster = Roster.query.filter_by(user_id=target_user.id, is_global=True).first()
        if target_roster:
            my_tribe_data = get_roster_data(target_roster)
            display_name = f"{target_user.username}'s Tribe"

    return render_template('global_standings.html',
                           full_global_leaderboard=lb,
                           my_tribe=my_tribe_data,
                           display_name=display_name)


@app.route('/global/draft')
def global_draft_page():
    # Guests can see the page
    roster = None
    if 'user_id' in session:
        roster = Roster.query.filter_by(user_id=session['user_id'], is_global=True).first()

    available = Survivor.query.filter_by(is_out=False).all()
    return render_template('global_draft.html', roster=roster, available=available, config=POINTS_CONFIG,
                           get_roster_data=get_roster_data, is_locked=is_locked())


@app.route('/save_global_draft', methods=['POST'])
def save_global_draft():
    if is_locked():
        flash("Drafting is closed! The Survivor 50 premiere has started.", "danger")
        return redirect(url_for('index'))

    picks = {
        'cap1': request.form.get('cap1'),
        'cap2': request.form.get('cap2'),
        'cap3': request.form.get('cap3'),
        'regs': request.form.getlist('regs')
    }

    # IF NOT LOGGED IN: Save to session and redirect
    if 'user_id' not in session:
        session['pending_tribe'] = picks
        flash("Tribe captured! Now create an account to secure your spot on the leaderboard.", "info")
        return redirect(url_for('signup'))

    # IF LOGGED IN: Normal Save
    user_exists = db.session.get(User, session['user_id'])
    if not user_exists:
        session.clear()
        return redirect(url_for('login'))

    r = Roster.query.filter_by(user_id=session['user_id'], is_global=True).first() or Roster(user_id=session['user_id'],
                                                                                             is_global=True)
    if not r.id:
        db.session.add(r)

    r.cap1_id = int(picks['cap1'])
    r.cap2_id = int(picks['cap2'])
    r.cap3_id = int(picks['cap3'])
    r.regular_ids = ",".join(picks['regs'])

    try:
        db.session.commit()
        flash("Global Tribe saved!", "success")
    except Exception as e:
        db.session.rollback()
        flash("Error saving draft.", "danger")
    return redirect(url_for('index'))


# --- PLAYER PROFILES ---
@app.route('/player/<string:slug>')
def player_profile(slug):
    if slug.isdigit():
        p = Survivor.query.get_or_404(int(slug))
    else:
        p = Survivor.query.filter_by(slug=slug).first_or_404()

    totals = {
        'surv': sum(1 for s in p.stats if s.survived),
        'imm': sum(1 for s in p.stats if s.immunity),
        'score': round(p.points, 1)
    }
    return render_template('player_profile.html', p=p, totals=totals)


@app.route('/admin/scoring', methods=['GET', 'POST'])
def admin_scoring():
    if not session.get('admin_authenticated'):
        if request.method == 'POST' and request.form.get('admin_pw') == os.getenv("ADMIN_PASSWORD", "JeffP"):
            session['admin_authenticated'] = True
            return redirect(url_for('admin_scoring'))
        return render_template('admin_login.html')

    # --- 1. HANDLE AJAX LIVE UPDATES ---
    # This fires every time you tap a checkbox in the browser
    if request.method == 'POST' and request.is_json:
        data = request.json
        p_id = data.get('player_id')
        cat = data.get('category')
        state = data.get('state')
        wn = int(data.get('week', 1))

        # Fetch existing record for this player/week or create a new one
        stat = WeeklyStat.query.filter_by(player_id=p_id, week=wn).first() or WeeklyStat(player_id=p_id, week=wn)

        if not stat.id:
            db.session.add(stat)

        # Prevent editing if the "Finalize" button was already clicked for this week
        if stat.is_locked:
            return jsonify({"success": False, "error": "This week is locked and cannot be edited."}), 403

        if hasattr(stat, cat):
            setattr(stat, cat, state)
            db.session.commit()

            # RE-CALCULATE TOTAL POINTS FOR THE PLAYER PROFILE
            p = db.session.get(Survivor, p_id)
            all_stats = WeeklyStat.query.filter_by(player_id=p_id).all()
            # We recalculate everything to ensure the Profile and Global Leaderboard stay in sync
            p.points = sum(s.calculate_for_league(POINTS_CONFIG) for s in all_stats)
            db.session.commit()

            return jsonify({"success": True, "new_total": round(p.points, 1)})
        return jsonify({"success": False}), 400

    # --- 2. HANDLE FULL PAGE ACTIONS (SYNC OR LOCK) ---
    survivors = Survivor.query.all()
    # Determine which week we are viewing from the URL or the Form
    view_week = int(request.form.get('week_num') or request.args.get('week', 1))

    if request.method == 'POST':
        if 'sync_all' in request.form:
            sync_players()
            flash("Cast synced from Google Sheets.", "success")
        else:
            # This is the "Finalize & Lock" logic
            for s in survivors:
                # Mark as out if the 'voted out' box was checked
                if request.form.get(f'voted_out_{s.id}'):
                    s.is_out = True

                # Lock every stat record for this week so AJAX can't change them anymore
                stat = WeeklyStat.query.filter_by(player_id=s.id, week=view_week).first()
                if stat:
                    stat.is_locked = True

            db.session.commit()
            flash(f"Week {view_week} has been finalized and locked!", "danger")

        return redirect(url_for('admin_scoring', week=view_week))

    # --- 3. PAGE DISPLAY LOGIC (GET REQUEST) ---
    # We need to send the CURRENT state of checkboxes to the HTML
    # We create a dictionary: { player_id: WeeklyStat_Object } for easy lookup in Jinja
    stats_list = WeeklyStat.query.filter_by(week=view_week).all()
    current_stats = {s.player_id: s for s in stats_list}

    # Check if the week itself is locked to disable the UI in HTML
    is_locked_week = any(s.is_locked for s in stats_list) if stats_list else False

    return render_template('admin_scoring.html',
                           survivors=survivors,
                           config=POINTS_CONFIG,
                           week=view_week,
                           current_stats=current_stats,
                           is_locked=is_locked_week)


@app.route('/robots.txt')
def robots():
    return send_from_directory(app.static_folder, 'robots.txt')


@app.route('/sitemap.xml', methods=['GET'])
def sitemap():
    pages = []
    now = datetime.now().strftime('%Y-%m-%d')
    main_functions = ['index', 'global_leaderboard', 'login']

    for func in main_functions:
        try:
            pages.append({
                "loc": url_for(func, _external=True),
                "lastmod": now,
                "priority": "1.0" if func == 'index' else "0.8"
            })
        except:
            continue

    try:
        players = Survivor.query.all()
        for p in players:
            loc_val = url_for('player_profile', slug=(p.slug or str(p.id)), _external=True)
            pages.append({
                "loc": loc_val,
                "lastmod": now,
                "priority": "0.7"
            })
    except Exception as e:
        print(f"Sitemap Error: {e}")

    sitemap_xml = render_template('sitemap_template.xml', pages=pages)
    return Response(sitemap_xml, mimetype='application/xml')


@app.route('/trends')
def draft_trends():
    submitted_rosters = Roster.query.filter(Roster.cap1_id.isnot(None)).all()
    total_count = len(submitted_rosters)
    if total_count == 0:
        return render_template('trends.html', stats=[], total_users=0,
                               error="No completed drafts found yet.")
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
                'name': s.name, 'slug': s.slug,
                'image': s.image_url,
                'total_pct': round((total_picks / total_count) * 100, 1),
                'gold_pct': round((gold_picks / total_count) * 100, 1),
                'count': total_picks
            })
    stats_list = sorted(stats_list, key=lambda x: x['total_pct'], reverse=True)
    return render_template('trends.html', stats=stats_list, total_users=total_count)


# --- NEW ADMIN LOOKUP TOOL ---
@app.route('/admin/roster-lookup')
def roster_lookup():
    if not session.get('admin_authenticated'):
        return "Unauthorized! Login at /admin/scoring", 401

    all_rosters = Roster.query.all()
    html = """
    <h1>Private League Roster Lookup</h1>
    <table border='1' style='border-collapse: collapse; width: 100%; text-align: left;'>
        <tr style='background-color: #eee;'>
            <th>Roster ID</th>
            <th>Username</th>
            <th>League Name (ID)</th>
            <th>Type</th>
            <th>Current Regulars</th>
        </tr>
    """
    for r in all_rosters:
        owner_name = r.owner.username if r.owner else "Unknown"
        if r.is_global:
            l_info = "GLOBAL CONTEST"
            r_type = "Global"
        else:
            league = db.session.get(League, r.league_id)
            l_info = f"{league.name} ({r.league_id})" if league else "Orphaned Roster"
            r_type = "Private League"

        html += f"<tr><td><b>{r.id}</b></td><td>{owner_name}</td><td>{l_info}</td><td>{r_type}</td><td>{r.regular_ids}</td></tr>"

    html += "</table><br><h2>Player ID List</h2>"
    players = Survivor.query.all()
    for p in players:
        html += f"{p.id}: {p.name} | "

    return html


# --- AGGRESSIVE ROSTER FIX ROUTE ---
@app.route('/admin/force-add-player/<int:roster_id>/<int:player_id>')
def force_add_player(roster_id, player_id):
    if not session.get('admin_authenticated'):
        return "Unauthorized", 401

    # 1. Force clear cache and fetch fresh
    db.session.expire_all()
    roster = db.session.get(Roster, roster_id)
    if not roster:
        return f"Error: Roster ID {roster_id} not found.", 404

    # 2. Logic to update the string
    old_ids = roster.regular_ids or "Empty"
    current_list = [rid.strip() for rid in (roster.regular_ids or "").split(',') if rid.strip()]

    if str(player_id) not in current_list:
        current_list.append(str(player_id))
        roster.regular_ids = ",".join(current_list)

        try:
            db.session.add(roster)
            db.session.commit()
            db.session.refresh(roster)
            return f"""
                <h3>Success!</h3>
                <p><b>Roster ID:</b> {roster_id}</p>
                <p><b>Before:</b> {old_ids}</p>
                <p><b>After:</b> {roster.regular_ids}</p>
                <a href='/admin/roster-lookup'>Back to Lookup</a> | <a href='/'>Go Home</a>
            """
        except Exception as e:
            db.session.rollback()
            return f"Database Error: {str(e)}"

    return f"Player {player_id} is already in Roster {roster_id}."


@app.route('/nuke_and_pave')
def nuke_and_pave():
    db.drop_all()
    db.create_all()
    sync_players()
    return "Database reset! <a href='/'>Go Home</a>"


@app.route('/admin/fix-walshymon')
def fix_walshymon():
    if not session.get('admin_authenticated'):
        return "Unauthorized", 401

    # Specifically target Roster 156
    roster = db.session.get(Roster, 156)
    if not roster:
        return "Roster 156 not found.", 404

    roster.cap1_id = 4  # Gold
    roster.cap2_id = 2  # Silver
    roster.cap3_id = 11  # Bronze
    roster.regular_ids = "8,13,19"
    roster.league_id = 14
    roster.is_global = False

    try:
        db.session.commit()
        return """
            <div style="font-family:sans-serif; padding:20px;">
                <h1 style="color: #2ecc71;">Walshymon Lineup Fixed!</h1>
                <p><b>Roster ID:</b> 156</p>
                <p><b>Captains:</b> 4, 2, 11</p>
                <p><b>Regulars:</b> 8, 13, 19</p>
                <br>
                <a href='/league/COMEONIN' style="padding:10px; background:#3498db; color:white; text-decoration:none; border-radius:5px;">Go to Dashboard</a>
            </div>
        """
    except Exception as e:
        db.session.rollback()
        return f"Database Error: {str(e)}"


# --- MIGRATION & STARTUP BLOCK ---
with app.app_context():
    db.create_all()
    # Migration: Add slug if missing
    try:
        db.session.execute(text("SELECT slug FROM survivor LIMIT 1"))
    except Exception:
        db.session.rollback()
        try:
            db.session.execute(text("ALTER TABLE survivor ADD COLUMN slug VARCHAR(100) UNIQUE"))
            db.session.commit()
            sync_players()
        except Exception as e:
            print(f"Slug Migration Error: {e}")

    # Migration: Add is_locked to WeeklyStat if missing
    try:
        db.session.execute(text("SELECT is_locked FROM weekly_stat LIMIT 1"))
    except Exception:
        db.session.rollback()
        try:
            db.session.execute(text("ALTER TABLE weekly_stat ADD COLUMN is_locked BOOLEAN DEFAULT FALSE"))
            db.session.commit()
        except Exception as e:
            print(f"Is_Locked Migration Error: {e}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8080)))