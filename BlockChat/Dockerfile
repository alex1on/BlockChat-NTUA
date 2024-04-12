FROM python:3.12

WORKDIR /app

# Install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

ENV DOCKER_ENV=1

CMD ["python", "./client.py", "node", "0.0.0.0", "5000", "3"]