from keras.models import load_model  # TensorFlow is required for Keras to work
from PIL import Image, ImageOps  # Install pillow instead of PIL
import numpy as np
import os 

# Disable scientific notation for clarity
np.set_printoptions(suppress=True)

filepath = os.path.join(os.path.abspath(os.path.dirname(__file__)))
print(filepath)
# Load the model
model = load_model(f"{filepath}/keras_model.h5", compile=False)

# Load the labels
class_names = open(f"{filepath}/labels.txt", "r").readlines()

def classify_img(img_src):
# Create the array of the right shape to feed into the keras model
# The 'length' or number of images you can put into the array is
# determined by the first position in the shape tuple, in this case 1
    data = np.ndarray(shape=(1, 224, 224, 3), dtype=np.float32) # 이미지가 들어갈 텅 빈 도회지 만든다

    # Replace this with the path to your image
    image = Image.open(img_src).convert("RGB")  # 이미지 불러온다

    # resizing the image to be at least 224x224 and then cropping from the center
    size = (224, 224) # 이미지를 원래 모델이 학습했던 사이즈로 규격화한다 
    image = ImageOps.fit(image, size, Image.Resampling.LANCZOS) # 리샘플링

    # turn the image into a numpy array
    image_array = np.asarray(image) # 텅빈 도화지 위에 입힙니다

    # Normalize the image
    normalized_image_array = (image_array.astype(np.float32) / 127.5) - 1  # 모델이 학습한 전체 이미지들의 평균값(명도, 채도)으로 변환합니다

    # Load the image into the array
    data[0] = normalized_image_array

    # Predicts the model
    prediction = model.predict(data) # 모델에 넣습니다 그리고 추론의 결과를 받습니다 [0.3, 0.7]
    index = np.argmax(prediction) # 가장 value가 큰 방의 index를 찾습니다 
    class_name = class_names[index] # 그 인덱스의 label.txt의 줄번호(방번호)를 찾습니다
    confidence_score = prediction[0][index]  # 가장 큰 값이 있는 추론 결과

    result = {"Class": class_name[2:], "ConfidenceScore": confidence_score}
# Print prediction and confidence score
# print("Class:", class_name[2:], end="") # ["0 mask", "1 nomask"] -> "0 "을 제외한 그 다음 글자들을 출력합니다 
# print("Confidence Score:", confidence_score) # 추론 결과도 출력합니다
    return result