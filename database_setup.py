from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key = True)
    name = Column(String(80), nullable = False)
    email = Column(String(250), nullable = False)
    picture = Column(String(250))


class Sport(Base):
    __tablename__ = 'sport'

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'id'           : self.id,
       }

class League(Base):
    __tablename__ = 'league'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    sport_id = Column(Integer,ForeignKey('sport.id'))
    sport = relationship(Sport)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)


    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'id'           : self.id,
       }

class Team(Base):
    __tablename__ = 'team'


    name =Column(String(200), nullable = False)
    id = Column(Integer, primary_key = True)
    description = Column(String(500), nullable=True)
    league_name = Column(Integer, ForeignKey('league.name'))
    league = relationship(League)
    sport_id = Column(Integer,ForeignKey('sport.id'))
    sport = relationship(Sport)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)


    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'description'  : self.description,
           'id'           : self.id
       }



engine = create_engine('sqlite:///sports.db')


Base.metadata.create_all(engine)
