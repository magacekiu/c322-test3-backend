# Use an official lightweight Java image.
FROM openjdk:17-slim

# Install Maven
RUN apt-get update && \
    apt-get install -y maven && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy the Maven configuration
COPY ./pom.xml ./pom.xml

# Copy the source code
COPY ./src ./src

# Build the application
RUN mvn package -DskipTests

# Run the jar file 
ENTRYPOINT ["java","-jar","/app/target/c322-test3-backend-0.0.1-SNAPSHOT.jar"]

