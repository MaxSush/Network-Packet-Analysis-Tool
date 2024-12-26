from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB limit
    from .routes import main
    app.register_blueprint(main)
    return app
