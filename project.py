# only google plus login
from flask import Flask, render_template, request, redirect
from flask import jsonify, url_for, flash


from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Sport, League, Team, User

# imports for function and decorators of login authentication
from functools import wraps
from flask import g, request, redirect, url_for

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']


# Connect to Database and create database session
engine = create_engine('sqlite:///sports.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# usefull functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getLeagueName(league_id):
    league = session.query(League).filter_by(id=league_id).one()
    return league.name


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# login authentication


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' in login_session:
            return f(*args, **kwargs)
        else:
            return render_template('login0.html',
                                   error="Login first!!!! \
                                   You are not allowed to access it")
    return decorated_function

# login function


@app.route('/')
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)

# fb login


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.4/me"
    # strip expire tag from access token
    token = result.split("&")[0]

    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token mst be stored in d login_session in order to properly logout,
    # let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: \
    150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output

# fb logout


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = ('https://graph.facebook.com/%s/permissions?access_token=%s'
           % (facebook_id, access_token))
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"

# googe login


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current \
                                            user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: \
        150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# google logout


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session['access_token']
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = ('https://accounts.google.com/o/oauth2/revoke?token=%s'
           % login_session['access_token'])
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:

    	response = make_response(json.dumps('Failed to revoke token \
                                         for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

# show list of all the sports


@app.route('/sport')
def showSports():
    sports = session.query(Sport).order_by(asc(Sport.name))
    if 'username' not in login_session:
        return render_template('publicsport.html', sports=sports)
    else:
        return render_template('sport.html', sports=sports)

# two option inside sport. 1. leagues 2. teams


@app.route('/sport/<int:sport_id>/')
@login_required
def showSportPage(sport_id):
    sport = session.query(Sport).filter_by(id=sport_id).one()
    return render_template('sportpage.html', sport=sport)

# create new sport


@app.route('/sport/new/', methods=['GET', 'POST'])
@login_required
def newSport():
    if request.method == 'POST':
        newSport = Sport(name=request.form['name'],
                         user_id=login_session['user_id'])
        session.add(newSport)
        flash('New Sport %s Successfully added' % newSport.name)
        session.commit()
        return redirect(url_for('showSports'))
    else:
        return render_template('newsport.html')

# edit sport


@app.route('/sport/<int:sport_id>/edit/', methods=['GET', 'POST'])
@login_required
def editSport(sport_id):
    editedSport = session.query(Sport).filter_by(id=sport_id).one()
    if editedSport.user_id != login_session['user_id']:
        return render_template('sport.html',
                               error="You are not allowed to EDIT it")

    if request.method == 'POST':
        if request.form['name']:
            editedSport.name = request.form['name']
            session.add(editedSport)
            session.commit()
            flash('Sport Successfully Edited %s' % editedSport.name)
            return redirect(url_for('showSports'))
    else:
        return render_template('editsport.html', editedSport=editedSport)

# delete sport and its all members


@app.route('/sport/<int:sport_id>/delete/', methods=['GET', 'POST'])
@login_required
def deleteSport(sport_id):
    sportToDelete = session.query(Sport).filter_by(id=sport_id).one()
    leagues = session.query(League).filter_by(sport_id=sport_id).all()
    teams = session.query(Team).filter_by(sport_id=sport_id).all()
    if sportToDelete.user_id != login_session['user_id']:
        return render_template('sport.html',
                               error="You are not allowed to DELETE it")
    if request.method == 'POST':
        session.delete(sportToDelete)
        flash('%s Successfully Deleted' % sportToDelete.name)
        session.commit()
        # if sport gets deleted then deleted all leagues of that sport
        # and all teams of that sport
        if leagues:
            for league in leagues:
                session.delete(league)
                session.commit()
        if teams:
            for team in teams:
                session.delete(team)
                session.commit()

        return redirect(url_for('showSports'))
    else:
        return render_template('delete.html', sport=sportToDelete)

# show leagues


@app.route('/sport/<int:sport_id>/league')
@login_required
def showLeagues(sport_id):
    sport = session.query(Sport).filter_by(id=sport_id).one()
    leagues = session.query(League).filter_by(sport_id=sport_id).all()
    creator = getUserInfo(sport.user_id)
    return render_template('league.html', leagues=leagues,
                           sport=sport, creator=creator)

# create new league


@app.route('/sport/<int:sport_id>/league/new', methods=['GET', 'POST'])
@login_required
def newLeague(sport_id):
    sport = session.query(Sport).filter_by(id=sport_id).one()
    if request.method == 'POST':
        newLeague = League(name=request.form['leaguename'],
                           sport_id=sport_id,
                           user_id=login_session['user_id'])
        session.add(newLeague)
        flash('New Sport %s Successfully added' % newLeague.name)
        session.commit()
        return redirect(url_for('showLeagues', sport_id=sport_id))
    else:
        return render_template('newleague.html', sport=sport)

# edit league


@app.route('/sport/<int:sport_id>/league/<int:league_id>/edit',
           methods=['GET', 'POST'])
@login_required
def editLeague(sport_id, league_id):
    editedLeague = session.query(League).filter_by(id=league_id).one()
    sport = session.query(Sport).filter_by(id=sport_id).one()
    teams = session.query(Team).filter_by(league_name=editedLeague.name)
    if login_session['user_id'] != editedLeague.user_id:
        return render_template('league.html', sport=sport,
                               error="You are not allowed to EDIT this League")
    if request.method == 'POST':
        if request.form['name']:
            editedLeague.name = request.form['name']
            session.add(editedLeague)
            session.commit()
            # as league gets changed,
            # we should also change teams' "league_name"
            if teams:
                for team in teams:
                    team.league_name = editedLeague.name
                    session.add(team)
                    session.commit()
            flash('League Successfully Edited')
            return redirect(url_for('showLeagues', sport_id=sport_id))
    else:
        return render_template('editleague.html', sport_id=sport_id,
                               league_id=league_id, editedLeague=editedLeague)

# delete league


@app.route('/sport/<int:sport_id>/league/<int:league_id>/delete/',
           methods=['GET', 'POST'])
@login_required
def deleteLeague(sport_id, league_id):
    sport = session.query(Sport).filter_by(id=sport_id).one()
    leagueToDelete = session.query(League).filter_by(id=league_id).one()
    teams = session.query(Team).filter_by(league_name=leagueToDelete.name)
    if leagueToDelete.user_id != login_session['user_id']:
        return render_template('league.html', sport=sport,
                               error="You are not allowed to \
                               DELETE this League")
    if request.method == 'POST':
        session.delete(leagueToDelete)
        flash('%s Successfully Deleted' % leagueToDelete.name)
        session.commit()
        # as league gets changed, we should also change teams' "league_name"
        if teams:
            for team in teams:
                team.league_name = "No league"
                session.add(team)
                session.commit()
        return redirect(url_for('showLeagues', sport_id=sport_id))
    else:
        return render_template('delete.html',
                               league=leagueToDelete, sport=sport)

# show teams only in appropriate league


@app.route('/sport/<int:sport_id>/league/<int:league_id>/')
@app.route('/sport/<int:sport_id>/league/<int:league_id>/team')
@login_required
def showTeamsLeague(sport_id, league_id):
    sport = session.query(Sport).filter_by(id=sport_id).one()
    league = session.query(League).filter_by(id=league_id).one()
    teams = session.query(Team).filter_by(league_name=league.name).all()
    creator = getUserInfo(league.user_id)
    return render_template('teamleague.html', teams=teams,
                           league=league, sport=sport, creator=creator)

# create new team


@app.route('/sport/<int:sport_id>/<int:league_id>/team/new',
           methods=['GET', 'POST'])
@login_required
def newTeam(sport_id, league_id):
    sport = session.query(Sport).filter_by(id=sport_id).one()
    leagues = session.query(League).filter_by(sport_id=sport_id).all()
    if request.method == 'POST':
        newTeam = Team(name=request.form['teamname'],
                       description=request.form['description'],
                       league_name=request.form['leaguename'],
                       sport_id=sport_id,
                       user_id=login_session['user_id'])
        session.add(newTeam)
        # flash('New Sport %s Successfully added' % newTeam.name)
        session.commit()
        if not league_id == 0:
            return redirect(url_for('showTeamsLeague', sport_id=sport_id,
                            league_id=league_id))
        else:
            return redirect(url_for('showTeams', sport_id=sport_id))
    else:
        if not league_id == 0:
            league_name = getLeagueName(league_id)
            return render_template('newteam.html', sport=sport,
                                   league_name=league_name, leagues=leagues)
        else:
            return render_template('newteam.html', sport=sport,
                                   leagues=leagues)

# edit team


@app.route('/sport/<int:sport_id>/team/<int:team_id>/\
           edit', methods=['GET', 'POST'])
@login_required
def editTeam(sport_id, team_id):
    editedTeam = session.query(Team).filter_by(id=team_id).one()
    leagues = session.query(League).filter_by(sport_id=sport_id).all()
    sport = session.query(Sport).filter_by(id=sport_id).one()
    if login_session['user_id'] != editedTeam.user_id:
        return render_template('team.html', sport=sport,
                               error="You are not allowed to EDIT this Team")
    if request.method == 'POST':
        if request.form['teamname']:
            editedTeam.name = request.form['teamname']
        if request.form['leaguename']:
            editedTeam.league_name = request.form['leaguename']
        if request.form['description']:
            editedTeam.description = request.form['description']
        session.add(editedTeam)
        session.commit()
        flash('Team Successfully Edited')
        return redirect(url_for('showSportPage', sport_id=sport_id))
    else:
        return render_template('editteam.html', sport=sport, leagues=leagues,
                               editedTeam=editedTeam)

# delete team


@app.route('/sport/<int:sport_id>/team/<int:team_id>/\
           delete', methods=['GET', 'POST'])
@login_required
def deleteTeam(sport_id, team_id):
    sport = session.query(Sport).filter_by(id=sport_id).one()
    teamToDelete = session.query(Team).filter_by(id=team_id).one()
    if teamToDelete.user_id != login_session['user_id']:
        return render_template('team.html', sport=sport,
                               error="You are not allowed to DELETE this Team")
    if request.method == 'POST':
        session.delete(teamToDelete)
        flash('%s Successfully Deleted' % teamToDelete.name)
        session.commit()
        return redirect(url_for('showTeams', sport_id=sport_id))
    else:
        return render_template('delete.html', sport=sport, team=teamToDelete)

# show team info page


@app.route('/sport/<int:sport_id>/team/<int:team_id>')
@login_required
def showTeampage(sport_id, team_id):
    sport = session.query(Sport).filter_by(id=sport_id).one()
    team = session.query(Team).filter_by(id=team_id).one()
    creator = getUserInfo(team.user_id)
    return render_template('teampage.html', team=team,
                           sport=sport, creator=creator)

# show all the teams in appropriate sport without considering leagues


@app.route('/sport/<int:sport_id>/teams')
@login_required
def showTeams(sport_id):
    sport = session.query(Sport).filter_by(id=sport_id).one()
    teams = session.query(Team).filter_by(sport_id=sport_id).all()
    creator = getUserInfo(sport.user_id)
    return render_template('team.html', teams=teams,
                           sport=sport, creator=creator)

# Disconnect based on provider


@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            # google credential are getting deleted in gdisconnect function
            #  so not using del login_session here as below
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
            del login_session['username']
            del login_session['email']
            del login_session['picture']
            del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showLogin'))
    else:
        flash("You were not logged in")


# JSON APIs to view Restaurant Information


# list of all the sports
@app.route('/sport/JSON')
def sportsJSON():
    sports = session.query(Sport).all()
    return jsonify(sports=[r.serialize for r in sports])


# list of leagues inside specific sports
@app.route('/sport/<int:sport_id>/league/JSON')
def leaguesJSON(sport_id):
    sport = session.query(Sport).filter_by(id=sport_id).one()
    leagues = session.query(League).filter_by(sport_id=sport_id).all()
    return jsonify(League=[i.serialize for i in leagues])


# list of teams inside specific leagues
@app.route('/sport/<int:sport_id>/league/<int:league_id>/teams/JSON')
def leagueteamJSON(sport_id, league_id):
    sport = session.query(Sport).filter_by(id=sport_id).one()
    league = session.query(League).filter_by(id=league_id).one()
    teams = session.query(Team).filter_by(league_name=league.name).all()
    return jsonify(Team=[i.serialize for i in teams])
    # return jsonify(Menu_Item = Menu_Item.serialize)


# list of teams inside specific sports
@app.route('/sport/<int:sport_id>/teams/JSON')
def sportteamJSON(sport_id):
    sport = session.query(Sport).filter_by(id=sport_id).one()
    teams = session.query(Team).filter_by(sport_id=sport_id).all()
    return jsonify(Team=[i.serialize for i in teams])

# info of individual team


@app.route('/team/<int:team_id>/JSON')
def teamJSON(team_id):
    # sport = session.query(Sport).filter_by(id = restaurant_id).one()
    team = session.query(Team).filter_by(id=team_id).one()
    return jsonify(team=team.serialize)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
