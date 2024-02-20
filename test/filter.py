# from datetime import datetime

# ## 필터를 템플릿에서 사용하는 법 어디든 별도 파일에 작성하고 
# ## __init__.py의 create_app() 안에 등록해주면 끝 

# ## 함수를 만들어서 함수명을 이름처럼 사용합니다
# def format_datetime(value, fmt="%Y년 %m월 %d일 %H:%M"):
#     return datetime.strptime(value, fmt)
import locale
locale.setlocale(locale.LC_ALL, '')

def format_datetime(value, fmt='%Y년 %m월 %d일 %p %I:%M'):
    return value.strftime(fmt)