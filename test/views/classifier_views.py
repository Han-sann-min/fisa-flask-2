from flask import Flask, render_template, Blueprint, request
import os
from ..ml_model import classify_img
import boto3 
import config
import io
# 1. Blueprint로 classifier라는 bp를 만들어주세요
classifier = Blueprint("classifier", __name__, url_prefix="/classifier")

@classifier.route("/upload", methods=['GET', 'POST'])
def upload_file():
    # 파일이 함께 온 경우 (POST)
    if request.method == "POST":
    # 만약에 파일이 없으면 파일이 없습니다 메시지 출력
        if 'file' not in request.files:
            return "파일이 없습니다", 400
        # 파일이 어떤 방식으로 왔는지 확인
        file = request.files['file']

        file_name = file.filename
        bucket = config.BUCKET_NAME
        key = f"uploads/{file_name}"
        s3_client = boto3.client('s3',
                        aws_access_key_id=config.AWS_ACCESS_KEY,
                        aws_secret_access_key=config.AWS_SECRET_KEY,
                        region_name=config.AWS_DEFAULT_REGION
                        )
        
        s3_client.upload_fileobj(file, bucket, key)

        #  image_url = # s3객체의 엔드포인트를 변경되도록 저장
        image_url = f"https://{config.BUCKET_NAME}.s3.{config.AWS_DEFAULT_REGION}.amazonaws.com/{key}"

        # s3의 객체를 가져옴
        object = s3_client.get_object(Bucket=bucket, Key=key)
        
        # S3는 파일이 아니라 Object라는 이름으로 불리우는 binary 형태로 데이터를 저장한다
        object_content = object['Body'].read()
        file_stream = io.BytesIO(object_content)

        # ml_model.py에 있는 모델 추론 함수를 실행합니다
        result = classify_img(file_stream)

        # 그 결과를 화면단에 뿌립니다. 이미지와, 추론결과를 달아서 
        return render_template('ml_model/result.html', result=result, filename=image_url )
    # 그냥 텅 빈 파일 업로드용 화면을 보내줍니다.
    return render_template("ml_model/upload.html")