from flask import Flask, flash, request, redirect, render_template
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FileField
from wtforms.validators import Required,Optional,IPAddress

from updated import AutoSnort
from werkzeug.utils import secure_filename
import os


ALLOWED_EXTENSIONS = set(['pcap'])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app = Flask(__name__)
# Flask-WTF requires an enryption key - the string can be anything
app.config['SECRET_KEY'] = 'some?bamboozle#string-foobar'
# Flask-Bootstrap requires this line
Bootstrap(app)
# this turns file-serving to static, using Bootstrap files installed in env
# instead of using a CDN
app.config['BOOTSTRAP_SERVE_LOCAL'] = True

# all Flask routes below

#class NameForm(FlaskForm):
 #   src_ip = StringField('Enter Source IP', validators=[Optional(),IPAddress(ipv4=True, ipv6=False, message="Not an IPV4 address")], render_kw={"placeholder": "Optional"})
 #   src_port = StringField('Enter Source Port', validators=[Optional()], render_kw={"placeholder": "Optional"})
  #  dest_ip = StringField('Enter Dest IP', validators=[Optional(),IPAddress(ipv4=True, ipv6=False, message="Not an IPV4 address")], render_kw={"placeholder": "Optional"})
   # dest_port = StringField('Enter Dest Port', validators=[Optional()], render_kw={"placeholder": "Optional"})
#    Protocol = StringField('Enter Protocol', validators=[Optional()], render_kw={"placeholder": "Optional"})
   # PcapFile = FileField('Upload Pcap File', validators=[Required()], render_kw={"placeholder": "Required"})
    
   # #submit = SubmitField('Submit')

    

# two decorators using the same function
#@app.route('/', methods=['GET', 'POST'])

x = " "
@app.route('/', methods=['POST'])
def upload_file():
    global x
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No file selected for uploading')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(os.getcwd(), filename))
            flash('File Successfully Uploaded. Processing...')
            if request.form['source'] == "":
                source = "any"
            else:
                source = request.form['source']

            if request.form['destination'] == "":
                destination = "any"
            else:
                destination = request.form['destination']
            
            if request.form['sourcePort'] == "":
                sourcePort = "any"
            else:
                sourcePort = request.form['sourcePort']
            
            if request.form['destinationPort'] == "":
                destinationPort = "any"
            else:
                destinationPort = request.form['destinationPort']
            
            if request.form['protocol'] == "":
                protocol = "tcp"
            else:
                protocol = request.form['protocol']

            a = AutoSnort(source,destination,sourcePort,destinationPort,protocol,filename)
            x =  a.execute()
            
            return redirect('/')
        else:
            flash('Allowed file type is pcap')
            #return redirect(request.url)
            return redirect('/')


@app.route('/', methods=['GET', 'POST'])
def index():
    #form = NameForm(request.form)
    message = x
    #if form.validate_on_submit():
     #   return redirect('index.html')
    return render_template('index.html',message=message)


# keep this as is
if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
