import express from "express";
import dotenv from "dotenv";
import redis from "ioredis";
import axios from "axios";
import cors from "cors";  

dotenv.config();
const app = express();

// Configurar CORS
app.use(cors({
  origin: 'http://localhost:5173', 
  methods: 'GET,POST,PUT,PATCH,DELETE',
  credentials: true  
}));

const redisClient = redis.createClient({
  host: process.env.REDIS_HOST || "127.0.0.1",
  port: process.env.REDIS_PORT || 6379,
});

redisClient.on("error", (error) => {
  console.error("Redis client error:", error);
});

redisClient.on("end", () => {
  console.log("Redis client connection closed");
});


const errorHandlingMiddleware = (err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).send(err.message || "Internal server error");
};

app.use(async (req, res, next) => {
  const token = req.headers.authorization.split(" ")[1];
  const userDataString = await redisClient.get(token);
  if (userDataString) {
    req.user = JSON.parse(userDataString);
    next();
  } else {
    res.status(401).send("Invalid or expired user key");
  }
});

const authorizationMiddleware = (requiredRole) => {
  return async (req, res, next) => {
    try {
      const availableRoles = req.user.resource_access.gatemaster.roles;
      if (!availableRoles.includes(requiredRole)) throw new Error();
      next();
    } catch (err) {
      res.status(403).send({ error: "access denied" });
    }
  };
};

app.use(errorHandlingMiddleware);
app.use(express.json());

app.get("/authenticate", (req, res) => {
  res.send("success");
});

app.get("/authorize", authorizationMiddleware("admin"), (req, res) => {
  res.send("success");
});

app.get("/apps", authorizationMiddleware("admin"), (req, res) => {
  res.send("Listado de las apps.");
});


//CREACION DE USUARIOS
app.post("/createuser", async (req, res) => {
  const {username, email, firstName, lastName } = req.body;

  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).send("Missing authorization header");
  const token = authHeader.split(" ")[1];
  try {
      await axios({
      method: "post",
      url: `http://keycloak:8080/admin/realms/master/users`,
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
      },
      data: {
        username,
        email,
        firstName,
        lastName,
        enabled: true,
      },
    });
    res.status(201).send("Usuario creado exitosamente");
    
  } catch (err) {
    console.error("Error details: "+ err.response + err.response.data + err.message);
    res.status(401).send("Ocurrió un error");
  }
});

//CONSEGUIR USUARIO
app.post("/getuser", async (req, res) => {
  const { username } = req.body;

  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).send("Missing authorization header");
  const token = authHeader.split(" ")[1];

  try {
    const { data } = await axios({
      method: "get",
      url: `http://keycloak:8080/admin/realms/master/users?username=${username}`,
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
      },
    });

    if (data.length > 0) {
      res.status(200).json(data[0]); 
    } else {
      res.status(404).send("Usuario no encontrado");
    }

  } catch (err) {
    console.error("Error details:", err.response ? err.response.data : err.message, err.message);
    res.status(500).send("Ocurrió un error al buscar el usuario");
  }
});

//SETEAR CONTRASEÑA
app.post("/setuserpassword", async (req, res) => {
  const { id, password } = req.body;

  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).send("Missing authorization header");

  const token = authHeader.split(" ")[1];

  try {
    const { status } = await axios({
      method: "put",
      url: `http://keycloak:8080/admin/realms/master/users/${id}/reset-password`,
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
      },
      data: {
        type: "password",
        temporary: false, // Cambiar a true si quieres que sea temporal
        value: password,
      },
    });

    if (status === 204) {
      res.status(200).send("Contraseña actualizada exitosamente");
    } else {
      res.status(500).send("Ocurrió un error al actualizar la contraseña");
    }

  } catch (err) {
    console.error("Error details: "+ err.response + err.response.data + err.message);
    res.status(500).send("Ocurrió un error al procesar la solicitud");
  }
});

//CONSIGUE TODOS LOS USUARIOS
app.get("/getallusers", async (req, res) => {

  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).send("Missing authorization header");

  const token = authHeader.split(" ")[1]; 

  try {
    
    const { data } = await axios({
      method: "get",
      url: `http://keycloak:8080/admin/realms/master/users`,
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
      },
    });

    if (data.length > 0) {
      res.status(200).json(data); 
    } else {
      res.status(404).send("No se encontraron usuarios");
    }

  } catch (err) {
    console.error("Detalles del error:", err.response ? err.response.data : err.message, err.message);
    res.status(500).send("Ocurrió un error al obtener los usuarios");
  }
});

//MODIFICAR UN USUARIO

app.put("/updateuser", async (req, res) => {
  const {userId, email, firstName, lastName } = req.body;

  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).send("Missing authorization header");
  const token = authHeader.split(" ")[1];

  try {
    
    await axios({
      method: "put",
      url: `http://keycloak:8080/admin/realms/master/users/${userId}`,
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
      },
      data: {
        email,
        firstName,
        lastName,
        enabled: true,
      },
    });

    res.status(200).send("Usuario actualizado exitosamente");
  } catch (err) {
    console.error("Error details:", err.response ? err.response.data : err.message);
    res.status(500).send("Ocurrió un error al actualizar el usuario");
  }
});



app.put("/disableuser", async (req, res) => {
  const { username } = req.body; 
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).send("Missing authorization header");
  const token = authHeader.split(" ")[1];

  try {
    const { data } = await axios({
      method: "get",
      url: `http://keycloak:8080/admin/realms/master/users?username=${username}`,
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
      },
    });

    if (data.length === 0) {
      return res.status(404).send("Usuario no encontrado");
    }

    const userId = data[0].id; 

    await axios({
      method: "put",
      url: `http://keycloak:8080/admin/realms/master/users/${userId}`,
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
      },
      data: {
        ...data[0], 
        enabled: false, 
      },
    });

    res.status(200).send("Usuario deshabilitado exitosamente");
  } catch (err) {
    console.error("Error details:", err.response ? err.response.data : err.message);
    res.status(500).send("Ocurrió un error al deshabilitar al usuario");
  }
});

const port = process.env.PORT || 3002;

app.listen(port, () => {
  console.log(`gatemaster listening on port ${port}`);
});
