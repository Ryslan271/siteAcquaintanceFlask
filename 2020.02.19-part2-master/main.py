import os
import smtplib as root
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from flask import Flask, render_template, redirect, request
from flask_login import LoginManager
from flask_restful import abort
from models import db_session

from models.users import User, RegisterForm, LoginForm, EditForm, PasswordForm, Delete_login


app = Flask(__name__)
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'
db_session.global_init('sqlite.db')
login_manager = LoginManager()
login_manager.init_app(app)

f = False

men_page, reg, adm, rig = None, None, None, None
url = 'smtp.mail.ru'
login1 = 'rupit.cod@mail.ru'
password = 'Qazwsxedc271'


@app.route("/")
def home():
    return render_template('Hello.html', flag=f, admi=adm, men=men_page)


@app.route("/Admin")
def admin():
    session = db_session.create_session()
    return render_template(
        'bases/admin.html',
        User=session.query(User).order_by(User.date.desc())
    )


@app.route("/Admin_bd")
def Admin_bd():
    session = db_session.create_session()
    return render_template(
        'bases/Admin_bd.html',
        User=session.query(User).order_by(User.date.desc())
    )


@app.route('/login', methods=['GET', 'POST'])
def login():
    global f, men_page, reg, adm, rig
    if not f or rig:
        reg = True
        form = LoginForm()
        if form.validate_on_submit():
            if form.login.data == 'admin':
                if form.password.data == '123' and form.mail.data == '123123':
                    f, adm = True, True
                    rig = None
                    return redirect('/Admin')
                else:
                    return render_template("Error/Admin_error.html", flag=f, admi=adm, men=men_page)

            session = db_session.create_session()
            if session.query(User).filter(User.login == form.login.data).first():
                if session.query(User).filter(User.hashed_password == (form.password.data + form.login.data)).first():
                    if session.query(User).filter(User.mail == form.mail.data).first():
                        if '@mail.ru' in form.mail.data:
                            f = True
                            rig = None
                            return render_template('Osnova.html', flag=f, men=men_page)
                        else:
                            return render_template('reg_and_log/edit.html', title='??????????????????????',
                                                   log=True,
                                                   form=form,
                                                   reg=reg,
                                                   new=True,
                                                   message="???? ?????????????????? ???????????? mail, ???????????? ?????????? @mail.ru")
                    else:
                        return render_template('reg_and_log/login.html', title='??????????????????????',
                                               log=True,
                                               form=form,
                                               reg=reg,
                                               mil=True,
                                               new=1,
                                               message="???????????????????????? ?? ?????????? mail ???????? ?? ???????? ????????????, "
                                                       " ?????????? ???????????????????????????????????")
                else:
                    return render_template('reg_and_log/login.html', title='??????????????????????',
                                           log=True,
                                           form=form,
                                           reg=reg,
                                           pas=True,
                                           new=1,
                                           message="???? ???????????????????? ????????????")
            else:
                return render_template('reg_and_log/login.html', title='??????????????????????',
                                       log=True,
                                       form=form,
                                       reg=reg,
                                       new=1,
                                       message="???????????? ???????????????????????? ???????? ?? ???????? ????????????, ?????????? ???????????????????????????????????")

        return render_template('reg_and_log/login.html', new=1, title='??????????????????????', form=form, reg=reg)
    else:
        abort(401)


@app.route('/register', methods=['GET', 'POST'])
def register():
    global f, reg, rig, url, login1, password
    reg = False
    if not rig:
        form = RegisterForm()
        if form.validate_on_submit():
            if form.password.data != form.password_again.data:
                return render_template('reg_and_log/register.html', title='??????????????????????',
                                       form=form,
                                       reg=reg,
                                       new=2,
                                       message="???????????? ???? ??????????????????")

            session = db_session.create_session()
            if session.query(User).filter(User.mail == form.mail.data).first():
                return render_template('reg_and_log/register.html', title='??????????????????????',
                                       form=form,
                                       reg=reg,
                                       log=True,
                                       new=2,
                                       message="???????????????????????? ?? ?????????? mail ?????? ????????")
            if '@mail.ru' not in form.mail.data:
                return render_template('reg_and_log/edit.html', title='??????????????????????',
                                       log=True,
                                       form=form,
                                       reg=reg,
                                       new=True,
                                       message="???? ?????????????????? ???????????? mail, ???????????? ?????????? @mail.ru")
            if session.query(User).filter(User.login == form.login.data).first():
                return render_template('reg_and_log/register.html', title='??????????????????????',
                                       form=form,
                                       reg=reg,
                                       log=True,
                                       new=2,
                                       message="?????????? ???????????????????????? ?????? ????????")
            if form.login.data == 'adminrys':
                return render_template('reg_and_log/register.html', title='??????????????????????',
                                       form=form,
                                       reg=reg,
                                       new=2,
                                       message="????????????????, ???? ???????? ?????????? ?????????? ?????????????? :)")
            if len(form.password.data) < 5 and len(form.login.data) < 5:
                return render_template('reg_and_log/register.html', title='??????????????????????',
                                       form=form,
                                       reg=reg,
                                       new=2,
                                       message="?????????? ?? ???????????? ???????????? ???????? ???????????? 5 ????????????????")

            if len(form.password.data) < 5:
                return render_template('reg_and_log/register.html', title='??????????????????????',
                                       form=form,
                                       reg=reg,
                                       new=2,
                                       message="???????????? ?????????????? ????????????????, ???? ???????????? ???????? ???????????? 5 ????????????????")
            if len(form.login.data) < 5:
                return render_template('reg_and_log/register.html', title='??????????????????????',
                                       form=form,
                                       reg=reg,
                                       new=2,
                                       message="?????????? ?????????????? ????????????????, ???? ???????????? ???????? ???????????? 5 ????????????????")

            toaddr = str(form.mail.data)

            topic = '???????????????????? ???? ?? ??????????????'
            message = '?????? ???? ?? ?????????? ????????????. ???????????? ???????? 1 ?????????????? ?????????????????????? ??????????:' \
                      ' ???? ????????????????????????  ?? ???????????????????? ?????????? XD'

            msg = MIMEMultipart()

            msg['Subject'] = topic
            msg['From'] = login1
            body = message
            msg.attach(MIMEText(body, 'plain'))

            server = root.SMTP_SSL(url, 465)
            server.login(login1, password)
            server.sendmail(login1, toaddr, msg.as_string())

            user = User(
                login=form.login.data,
                hashed_password=form.password.data,
                mail=form.mail.data
            )
            user.set_password(form.password.data)
            session.add(user)
            session.commit()
            f, rig = True, True
            return redirect('/')
        return render_template('reg_and_log/register.html', new=2, title='??????????????????????', form=form, reg=reg)
    else:
        abort(404)


@app.route('/new_mail', methods=['GET', 'POST'])
def new_mail():
    global url, login1, password
    form = EditForm()
    session = db_session.create_session()
    if form.validate_on_submit():
        user = session.query(User).filter(User.login == form.login.data).first()
        if user and user.check_password(form.password.data):
            if session.query(User).filter(User.login == form.login.data).first():
                if '@mail.ru' in form.mail.data:
                    user = session.query(User).filter(User.login == form.login.data).first()
                    user.mail = form.mail.data
                    session.commit()

                    toaddr = str(form.mail.data)
                    topic = '?????????? mail ?? ?????????????? XD'
                    message = '???? ???????????????? ???????? ???? ?????????? ???? ???????????????? ???? ?????????? ?????????? :D ' \
                              '???????????????? ??????????: RuPit'

                    msg = MIMEMultipart()

                    msg['Subject'] = topic
                    msg['From'] = login1
                    body = message
                    msg.attach(MIMEText(body, 'plain'))

                    server = root.SMTP_SSL(url, 465)
                    server.login(login1, password)
                    server.sendmail(login1, toaddr, msg.as_string())
                    return redirect('/login')
                else:
                    return render_template('reg_and_log/edit.html', title='??????????????????????',
                                           log=True,
                                           form=form,
                                           reg=reg,
                                           new=3,
                                           message="???? ?????????????????? ???????????? mail, ???????????? ?????????? @mail.ru")

            else:
                return render_template('reg_and_log/edit.html', title='??????????????????????',
                                       log=True,
                                       form=form,
                                       reg=reg,
                                       new=3,
                                       message="???????????? ???????????????????????? ???????? ?? ???????? ????????????, ?????????? ???????????????????????????????????")

        else:
            return render_template('reg_and_log/edit.html', title='??????????????????????',
                                   log=True,
                                   form=form,
                                   reg=reg,
                                   new=3,
                                   message="???? ???????????????????? ????????????")
    return render_template('reg_and_log/edit.html', new=3, title='?????????? mail', form=form, reg=reg)


@app.route('/new_pass', methods=['GET', 'POST'])
def new_pass():
    global url, login1, password
    form = PasswordForm()
    session = db_session.create_session()
    if form.validate_on_submit():
        if session.query(User).filter(User.mail == form.mail.data).first():
            if session.query(User).filter(User.login == form.login.data).first():
                if form.password.data == form.password_again.data:
                    if len(form.password.data) >= 5:
                        user = session.query(User).filter(User.login == form.login.data).first()
                        user.check_password = form.password.data
                        session.commit()

                        toaddr = str(form.mail.data)
                        topic = '???????????? ??????????????'
                        message = '???? ???????????????? ???????????? ???? ?????????? RuPit'

                        msg = MIMEMultipart()

                        msg['Subject'] = topic
                        msg['From'] = login1
                        body = message
                        msg.attach(MIMEText(body, 'plain'))

                        server = root.SMTP_SSL(url, 465)
                        server.login(login1, password)
                        server.sendmail(login1, toaddr, msg.as_string())
                        return redirect('/login')
                    else:
                        return render_template('reg_and_log/password.html', title='?????????? ????????????',
                                               form=form,
                                               reg=reg,
                                               new=4,
                                               message="???????????? ?????????????? ????????????????, ???? ???????????? ???????? ???????????? 5 ????????????????")
                else:
                    return render_template('reg_and_log/password.html', title='?????????? ????????????',
                                           form=form,
                                           reg=reg,
                                           new=4,
                                           message="???????????? ???? ??????????????????")
            else:
                return render_template('reg_and_log/password.html', title='?????????? ????????????',
                                       form=form,
                                       reg=reg,
                                       log=True,
                                       new=4,
                                       message="???????????????????????? ?? ?????????? login ?????? ?? ????????")
        else:
            return render_template('reg_and_log/password.html', title='?????????? ????????????',
                                   form=form,
                                   reg=reg,
                                   log=True,
                                   new=4,
                                   message="???????????????????????? ?? ?????????? mail ?????? ?? ????????")
    return render_template('reg_and_log/password.html', new=4, title='?????????? ????????????', form=form, reg=reg)


@app.route('/del_log', methods=['GET', 'POST'])
def del_log():
    global url, login1, password, men_page, reg, adm, rig, f
    form = Delete_login()
    session = db_session.create_session()
    if form.validate_on_submit():
        if session.query(User).filter(User.login == form.login.data).first():
            if session.query(User).filter(User.hashed_password == form.password.data + form.login.data).first():
                user = session.query(User).filter(User.login == form.login.data).first()
                session.delete(user)
                session.commit()

                toaddr = str(user.mail)
                topic = '?????????????? ????????????'
                message = '???? ?????????????? ?????????????? ???? ?????????? RuPit'

                msg = MIMEMultipart()

                msg['Subject'] = topic
                msg['From'] = login1
                body = message
                msg.attach(MIMEText(body, 'plain'))

                server = root.SMTP_SSL(url, 465)
                server.login(login1, password)
                server.sendmail(login1, toaddr, msg.as_string())
                f = False
                men_page, reg, adm, rig = None, None, None, None
                return redirect('/')
            else:
                return render_template('reg_and_log/deletelogin.html', title='???????????????? ????????????????',
                                       form=form,
                                       reg=reg,
                                       new=4,
                                       message="???????????? ???? ??????????????????")
        else:
            return render_template('reg_and_log/deletelogin.html', title='???????????????? ????????????????',
                                   form=form,
                                   reg=reg,
                                   log=True,
                                   new=4,
                                   message="???????????????????????? ?? ?????????? login ?????? ?? ????????")
    return render_template('reg_and_log/deletelogin.html', new=4, title='???????????????? ????????????????', form=form, reg=reg)


@app.route('/delete_log', methods=['GET', 'POST'])
def delete_log():
    global f, men_page, reg, adm, rig
    f = False
    men_page, reg, adm, rig = None, None, None, None
    return redirect('/')


@login_manager.user_loader
def load_user(user_id):
    session = db_session.create_session()
    return session.query(User).get(user_id)


@app.errorhandler(400)
def not_found_error(error):
    global f
    return render_template('Error/400.html', f=f), 400


@app.errorhandler(401)
def not_found_error(error):
    global f
    return render_template('Error/401.html', f=f), 401


@app.errorhandler(404)
def not_found_error(error):
    global f
    return render_template('Error/404.html', f=f), 404


@app.errorhandler(500)
def not_found_error(error):
    global f
    return render_template('Error/500.html', f=f), 500


@app.errorhandler(502)
def not_found_error(error):
    global f
    return render_template('Error/502.html', f=f), 502


@app.errorhandler(503)
def not_found_error(error):
    global f
    return render_template('Error/503.html', f=f), 503


if __name__ == '__main__':
    app.run(port=8080, host='127.0.0.1')