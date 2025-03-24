from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Regexp

class AddGISMapForm(FlaskForm):
    disaster_name = StringField('Disaster Name', validators=[DataRequired()])

    # Coordinates field with custom regex validator to ensure the format is "latitude, longitude"
    coordinates = StringField(
        'Coordinates',
        validators=[
            DataRequired(),
            Regexp(
                r'^-?\d+(\.\d+)?,\s*-?\d+(\.\d+)?$',  # regex to match valid latitude, longitude format
                message="Coordinates must be in the format 'latitude, longitude'"
            )
        ]
    )
    description = StringField('Description')
    submit = SubmitField('Add GIS Map')

