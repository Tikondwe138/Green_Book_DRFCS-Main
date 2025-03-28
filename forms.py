from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length

class AddGISMapForm(FlaskForm):
    disaster_name = StringField('Disaster Name', validators=[DataRequired()])
    coordinates = StringField('Coordinates (e.g., "[latitude, longitude]")', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired(), Length(max=255)])
    submit = SubmitField('Add GIS Map')
