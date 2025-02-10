FROM python:3.9-slim-bullseye
WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install gunicorn
COPY . /app
EXPOSE 8000
CMD ["gunicorn", "--workers", "1", "--bind", "0.0.0.0:8000", "app:app"]
