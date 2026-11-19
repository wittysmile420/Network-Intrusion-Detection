def create_app(test_config=None):
    from pathlib import Path
    from flask import Flask

    from .config import Config
    from .database import init_db
    from .web.routes import api

    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    Path(app.config["REPORT_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
    init_db(app.config["DATABASE"])
    app.register_blueprint(api)
    return app

