from brewCalc import db
from brewCalc.models import *

db.drop_all()
db.create_all()

# Test User
user = User(user='claudio',
            password='test', 
            email='claudio@brewer.com', 
            role='user', 
            first_name='Claudio', 
            last_name='Castello', 
            email_confirmed=True)

db.session.add(user)
db.session.commit()