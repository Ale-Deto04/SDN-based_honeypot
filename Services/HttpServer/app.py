from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = "secretkey123"

ADMIN_CREDS = {"admin": "admin"}

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/login", methods = ["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        if username in ADMIN_CREDS and ADMIN_CREDS[username] == password:
            session["user"] = username
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password", "error")
            return redirect(url_for("login"))

    return render_template('login.html')

@app.route("/login/dashboard")
def dashboard():
    if "user" not in session:
        flash("You need to log in first", "error")
        return redirect(url_for("login"))
    return render_template("dashboard.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Logged out successfully", "success")
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug = True, host = "0.0.0.0", port = 80)
