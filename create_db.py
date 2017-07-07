from brewCalc import db
from brewCalc.models import *

db.drop_all()
db.create_all()

p1 = User(user='claudio', password='test', email='claudio@brewer.com', role='user', first_name='Claudio', last_name='Castello')

db.session.add(p1)

db.session.commit()