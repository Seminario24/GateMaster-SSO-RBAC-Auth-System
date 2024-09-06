# API Gateway with Rate Limiting, Authentication, and Proxying

This project sets up an API Gateway using Express, with rate limiting, authentication middleware, and proxying to backend services. It also integrates Redis for caching authentication tokens.

### Prerequisites

- Node.js
- Redis
- Docker
- Docker Compose

### Installation

1. Clone the repository
2. Install dependencies:
	> npm install

3. Set up environment variables:

	> REDIS_HOST (default: 127.0.0.1)

	> REDIS_PORT (default: 6379)

	> PORT (default: 3000)

### Usage
1. Start the Redis server:
	- Read the documentation [here](https://redis.io/docs/latest/operate/oss_and_stack/install/install-redis/).

2. Run the API Gateway:
	> npm start

3. Start the services with Docker Compose:
	> docker-compose up

	This will:

	- Pull the necessary Docker images.
	- Set up the Node.js application container.
	- Set up the Redis container.

### Components
#### Rate Limiting

Limits each IP to 100 requests per minute to prevent abuse.

```javascript
import rateLimit from "express-rate-limit";
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: "Too many requests, please try again later.",
});
app.use(apiLimiter);
```

#### Redis Client

Connects to a Redis server for caching authentication tokens.

```javascript
import Redis from "ioredis";
const redisClient = new Redis({
  host: process.env.REDIS_HOST || "127.0.0.1",
  port: process.env.REDIS_PORT || 6379,
});
redisClient.on("error", (error) => {
  console.error("Redis client error:", error);
});
redisClient.on("end", () => {
  console.log("Redis client connection closed");
});

```

#### Authentication Middleware

Checks the validity of tokens and caches them in Redis.

```javascript
const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).send("Missing authorization header");
  const token = authHeader.split(" ")[1];
  let cachedData = await redisClient.get(token);
  if (cachedData) {
    return next();
  }
  try {
    const response = await axios.get(`${authUrl}/verifyToken`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const { data } = response;
    await redisClient.set(token, JSON.stringify(data));
    next();
  } catch (error) {
    console.log({ error });
    res.status(401).send("Invalid or expired token");
  }
};

```

#### Proxy Middleware

Sets up proxying to backend services with authentication.

```javascript
import { createProxyMiddleware } from "http-proxy-middleware";
const service1Url = "http://localhost:3002";

app.use(
  "/api/auth",
  createProxyMiddleware({
    target: authUrl,
    changeOrigin: true,
    pathRewrite: {
      "^/api/auth": "",
    },
  })
);

app.use(
  "/api/service1",
  authMiddleware,
  createProxyMiddleware({
    target: service1Url,
    changeOrigin: true,
    pathRewrite: {
      "^/api/service1": "",
    },
  })
);

```

#### Starting the Server

Starts the Express server on the specified port.

```javascript
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`API Gateway listening on port ${port}`);
});
```
