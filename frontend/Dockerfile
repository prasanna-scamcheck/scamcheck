FROM node:20-alpine AS build 
WORKDIR /app 
COPY package.json . 
RUN npm install 
COPY . . 
ARG REACT_APP_API_URL 
ENV REACT_APP_API_URL=$REACT_APP_API_URL 
RUN npm run build 
FROM node:20-alpine 
RUN npm install -g serve 
COPY --from=build /app/build /app/build 
WORKDIR /app 
CMD ["serve", "-s", "build", "-l", "8080"] 
