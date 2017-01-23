from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Sport, League, Team, User

engine = create_engine('sqlite:///sports.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
User1 = User(name="Brindal", email="brindalpatel70@gmail.com")
session.add(User1)
session.commit()



# sport1  ############ football ####
sport1 = Sport(user_id=1, name="football")
session.add(sport1)
session.commit()

league1 = League(user_id=1, sport_id=1, name="la liga")
session.add(league1)
session.commit()

league2 = League(user_id=1, sport_id=1, name="bundesliga")
session.add(league2)
session.commit()

league3 = League(user_id=1, sport_id=1, name="EPL")
session.add(league3)
session.commit()

team1 = Team(name="Real Madrid", sport_id=1, user_id=1, league_name="la liga")
session.add(team1)
session.commit()

team2 = Team(name="Barcelona", sport_id=1, user_id=1, league_name="la liga")
session.add(team2)
session.commit()

team3 = Team(name="Atletico Madrid", sport_id=1, user_id=1, league_name="la liga")
session.add(team3)
session.commit()

team4 = Team(name="Dortmund", sport_id=1, user_id=1, league_name="bundesliga")
session.add(team4)
session.commit()

team5 = Team(name="Bayern", sport_id=1, user_id=1, league_name="bundesliga")
session.add(team5)
session.commit()

team6 = Team(name="Hamburg", sport_id=1, user_id=1, league_name="bundesliga")
session.add(team6)
session.commit()

team7 = Team(name="Man Utd", sport_id=1, user_id=1, league_name="EPL")
session.add(team7)
session.commit()

team8 = Team(name="Liverpool", sport_id=1, user_id=1, league_name="EPL")
session.add(team8)
session.commit()

team9 = Team(name="Man City", sport_id=1, user_id=1, league_name="EPL")
session.add(team9)
session.commit()

team10 = Team(name="Tottenham", sport_id=1, user_id=1, league_name="EPL")
session.add(team10)
session.commit()

# sport2  ############ cricket ####
sport2 = Sport(user_id=1, name="cricket")
session.add(sport2)
session.commit()

league1 = League(user_id=1, sport_id=2, name="IPL")
session.add(league1)
session.commit()

team1 = Team(name="Mumbai Indians", sport_id=2, user_id=1, league_name="IPL")
session.add(team1)
session.commit()

team2 = Team(name="Delhi Daredevils", sport_id=2, user_id=1, league_name="IPL")
session.add(team2)
session.commit()

team3 = Team(name="Chennai Super King", sport_id=2, user_id=1, league_name="IPL")
session.add(team3)
session.commit()

team4 = Team(name="Rajasthan Royals", sport_id=2, user_id=1, league_name="IPL")
session.add(team4)
session.commit()


# sport3  ############ basketball ####
sport3 = Sport(user_id=1, name="basketball")
session.add(sport3)
session.commit()

league1 = League(user_id=1, sport_id=3, name="NBA")
session.add(league1)
session.commit()

league2 = League(user_id=1, sport_id=3, name="NBA D-League")
session.add(league2)
session.commit()

team1 = Team(name="Los Angeles Lakers", sport_id=3, user_id=1, league_name="NBA")
session.add(team1)
session.commit()

team2 = Team(name="Chicago Bulls", sport_id=3, user_id=1, league_name="NBA")
session.add(team2)
session.commit()

team3 = Team(name="New york Knicks", sport_id=3, user_id=1, league_name="NBA")
session.add(team3)
session.commit()

team4 = Team(name="Miami Heat", sport_id=3, user_id=1, league_name="NBA")
session.add(team4)
session.commit()

team5 = Team(name="San Antonio Spurs", sport_id=3, user_id=1, league_name="NBA")
session.add(team5)
session.commit()

team1 = Team(name="Santa cruz Warriors", sport_id=3, user_id=1, league_name="NBA D-League")
session.add(team1)
session.commit()

team2 = Team(name="Austin spurs", sport_id=3, user_id=1, league_name="NBA D-League")
session.add(team2)
session.commit()

team3 = Team(name="Los Angeles D-Fenders", sport_id=3, user_id=1, league_name="NBA D-League")
session.add(team3)
session.commit()

team4 = Team(name="Iowa Energy", sport_id=3, user_id=1, league_name="NBA D-League")
session.add(team4)
session.commit()


print "added teams and leagues!"
