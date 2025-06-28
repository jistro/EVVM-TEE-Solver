FROM python:3-slim

RUN pip install -U pip setuptools

WORKDIR /app

COPY requirements.txt ./

RUN pip install -r requirements.txt

COPY main.py ./

EXPOSE 8000

CMD ["fastapi", "run", "main.py", "--host", "0.0.0.0", "--port", "8000"]
