from flask import Flask
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
import datetime
import logging.config
import logging

# app.py인 곳을 입구로 찾아서 기본적으로 실행합니다
# 또는 FLASK_APP이라는 환경변수의 이름을 파일명으로 변경합니다
# set FLASK_APP=test 
# wsgi.py에 직접 키=밸류로 여러 환경변수들을 기입합니다.
from sqlalchemy import MetaData
import config

# db = SQLAlchemy()
migrate = Migrate()

naming_convention = {
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(column_0_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}

db = SQLAlchemy(metadata=MetaData(naming_convention=naming_convention))

def create_app():
    test= Flask(__name__)
    test.config.from_object(config)

    # ORM
    db.init_app(test)
    if test.config['SQLALCHEMY_DATABASE_URI'].startswith("sqlite"):
        migrate.init_app(test, db, render_as_batch=True)
    else:
        migrate.init_app(test, db)

    # create_app() 안에
    today_date = datetime.datetime.now().strftime("%Y-%m-%d")  
    if not test.debug: 
            # 즉 debug=true면 이는 false로서 아래 코드를 읽어옵니다.
            # 실제 상용화단계에서 로깅을 진행하라는 의미입니다.


            logging.config.dictConfig({
                'version': 1,
                'disable_existing_loggers': False,
                'formatters': {
                    'verbose': {  # 로그 출력 패턴 1
                        'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
                        'style': '{',
                    },
                    'simple': { # 로그 출력 패턴 2
                        'format': '{levelname} {message}',
                        'style': '{',
                    },
                },
                'handlers': {
                    'console': { # 콘솔에 출력하는 로그의 범위
                        'level': 'INFO',
                        'class': 'logging.StreamHandler',
                        'formatter': 'verbose',
                    },
                    'file': {
                        'level': 'DEBUG',
                        'encoding': 'utf-8',
                        'class': 'logging.handlers.RotatingFileHandler',
                        'filename': test.root_path + f'/logs/{today_date}-mysiteLog.log', # 이 파일에 로그를 수집할 예정
                        'formatter': 'verbose', # 적용시킨 로그 출력 패턴 1대로 수집
                        'maxBytes': 1024*1024*5, # 5 MB
                        'backupCount': 5,
                    },
                    'errors': { # 에러가 난 경우 별도 파일로 수집할 예정
                        'level': 'ERROR',
                        'encoding': 'utf-8',
                        'class': 'logging.FileHandler',
                        'filename': test.root_path + f'/logs/{today_date}-mysiteErrorLog.log', # logs 폴더 생성 필요
                        'formatter': 'simple', # 로그 출력 패턴 2대로 수집
                    },
                },
                'loggers': {
                    'flask.app': {  
                        'handlers': ['console', 'file'],
                        'level': 'DEBUG',
                        'propagate': True,
                    },
                    'flask.request': {
                        'handlers': ['errors'],
                        'level': 'ERROR',
                        'propagate': True,
                    },
                    'my': {
                        'handlers': ['console', 'file', 'errors'],
                        'level': 'INFO',
                    },
                },
            })    

        # 블루프린트

    from .views import main_views, board_views, answer_views, auth_views, classifier_views  # views 폴더 및의 main_views.py 임포트
    test.register_blueprint(main_views.bp)
    test.register_blueprint(board_views.board)
    test.register_blueprint(answer_views.answer)
    test.register_blueprint(auth_views.auth)
    test.register_blueprint(classifier_views.classifier)
    
    # 커스텀 필터 사용
    from test.filter import format_datetime
    test.jinja_env.filters['date_time'] = format_datetime
    
    return test