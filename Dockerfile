# Stage 1: Build the application
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build

# Set the working directory inside the container
WORKDIR /app

# Copy the project file and restore dependencies
COPY mbg-integration-docs-auth.csproj ./
RUN dotnet restore

# Copy the rest of the application code
COPY . ./

# Build the application
RUN dotnet publish -c Release -o /out

# Stage 2: Create the runtime image
FROM mcr.microsoft.com/dotnet/aspnet:9.0

# Set the working directory
WORKDIR /app

# Copy the published application from the build stage
COPY --from=build /out ./

# Expose the port the application runs on
EXPOSE 5000

# Start the application
ENTRYPOINT ["dotnet", "mbg-integration-docs-auth.dll"]