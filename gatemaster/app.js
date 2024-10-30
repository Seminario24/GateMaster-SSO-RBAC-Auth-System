import express from "express";
import dotenv from "dotenv";
import redis from "ioredis";
import axios from "axios";

import pkg from 'pg';
const { Pool } = pkg;

dotenv.config();
const app = express();
app.set('trust proxy', 1);

// Configurar CORS
app.use(cors({
  origin: 'http://localhost:5173', 
  methods: 'GET,POST,PUT,PATCH,DELETE',
  credentials: true  
}));

const pool = new Pool({
  user: "keycloak_db_user",
  host: "postgres",
  database: "keycloak_db",
  password: "keycloak_db_user_password",
  port: 5432,
});

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

//=============================================================================================
//                                 CONEXION A KEYCLOAK 
//=============================================================================================

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
    console.error("Error details: "+ err.response + err.message);
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

//MODIFICAR USUARIO
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

//DESHABILITAR USUARIO
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

//HABILITAR USUARIO
app.put("/enableuser", async (req, res) => {
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
        enabled: true,
      },
    });

    res.status(200).send("Usuario habilitado exitosamente");
  } catch (err) {
    console.error("Error details:", err.response ? err.response.data : err.message);
    res.status(500).send("Ocurrió un error al habilitar al usuario");
  }
});

// OBTENER ESTADO DE USUARIO

app.get("/getallusersstatus", async (req, res) => {
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

    const usersStatus = data.map(user => ({
      username: user.username,
      email: user.email,
      status: user.enabled ? "active" : "suspended"

    }));

    if (usersStatus.length > 0) {
      res.status(200).json(usersStatus);
    } else {
      res.status(404).send("No se encontraron usuarios");
    }

  } catch (err) {
    console.error("Detalles del error:", err.response ? err.response.data : err.message);
    res.status(500).send("Ocurrió un error al obtener los usuarios");
  }
});


//=============================================================================================
//                               CONEXION A LA BASE DE DATOS
//=============================================================================================

//APP

//CREAR APP
app.post("/createapp", async (req, res) => {
  const { app_id, app_name, app_description, app_version, created_by } = req.body;

  const client = await pool.connect();

  try {
    const insertQuery = `
      INSERT INTO tbl_App (app_id, app_name, app_description, app_version, created_by)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING app_id;
    `;

    const values = [app_id, app_name, app_description || null, app_version || null, created_by || null];

    const result = await client.query(insertQuery, values);

    res.status(201).json({ message: "Aplicación creada exitosamente", app_id: result.rows[0].app_id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);

    if (err.code === '23505') {
      res.status(409).send("El nombre de la aplicación ya existe");
    } else {
      res.status(500).send("Error al crear la aplicación");
    }
  } finally {
    client.release();
  }
});

//ACTUALIZAR APP
app.put("/updateapp/:id", async (req, res) => {
  const { id } = req.params;
  const { app_name, app_description, app_version, updated_by } = req.body;

  const client = await pool.connect();

  try {
    const updateQuery = `
      UPDATE tbl_App
      SET
        app_name = COALESCE($1, app_name),
        app_description = COALESCE($2, app_description),
        app_version = COALESCE($3, app_version),
        updated_by = COALESCE($4, updated_by),
        updated_on = CURRENT_TIMESTAMP
      WHERE app_id = $5
      RETURNING app_id;
    `;

    const values = [app_name, app_description, app_version, updated_by || null, id];

    const result = await client.query(updateQuery, values);

    if (result.rowCount === 0) {
      return res.status(404).send("Aplicación no encontrada");
    }

    res.status(200).json({ message: "Aplicación actualizada exitosamente", app_id: id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);

    if (err.code === '23505') {
      res.status(409).send("El nombre de la aplicación ya existe");
    } else {
      res.status(500).send("Error al actualizar la aplicación");
    }
  } finally {
    client.release();
  }
});

//OBTENER APP POR ID

app.get("/getapp/:id", async (req, res) => {
  const { id } = req.params;

  const client = await pool.connect();

  try {
    const selectQuery = `
      SELECT app_id, app_name, app_description, app_version, created_by, created_on, updated_by, updated_on
      FROM tbl_App
      WHERE app_id = $1;
    `;

    const result = await client.query(selectQuery, [id]);

    if (result.rows.length === 0) {
      return res.status(404).send("Aplicación no encontrada");
    }

    res.status(200).json(result.rows[0]);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al buscar la aplicación");
  } finally {
    client.release();
  }
});

//OBTENER APPS

app.get("/getallapps", async (req, res) => {
  const client = await pool.connect();

  try {
    const selectAllQuery = `
      SELECT app_id, app_name, app_description, app_version, created_by, created_on, updated_by, updated_on
      FROM tbl_App;
    `;

    const result = await client.query(selectAllQuery);

    res.status(200).json(result.rows);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al obtener las aplicaciones");
  } finally {
    client.release();
  }
});




//USUARIO

//CREAR USUARIO
app.post("/insertuser", async (req, res) => {
  const {
    allow,
    username,
    firstName,
    lastName,
    password,
    email,
    active,
    created_by,
    updated_by
  } = req.body;

  if (!username || !password || !email) {
    return res.status(400).send("Los campos username, password y email son obligatorios");
  }

  const client = await pool.connect();

  try {
    const insertQuery = `
      INSERT INTO tbl_User (allow, username, first_name, last_name, password, email, active, created_by, updated_by)
      VALUES ($1, $2, $3, $4, crypt($5, gen_salt('bf')), $6, $7, $8, $9)
      RETURNING user_id;
    `;
    const values = [
      allow || false,          
      username,
      firstName || null,
      lastName || null,
      password,               
      email,
      active || true,          
      created_by || null,
      updated_by || null
    ];

    const result = await client.query(insertQuery, values);
    const insertedUserId = result.rows[0].user_id;

    console.log("Usuario insertado con ID:", insertedUserId);
    res.status(201).json({ message: "Usuario insertado exitosamente", user_id: insertedUserId });

  } catch (err) {
    console.error("Database error: ", err.message);

    if (err.code === '23505') {
      res.status(409).send("El nombre de usuario o correo electrónico ya existe");
    } else {
      res.status(500).send("Error al insertar el usuario en la base de datos");
    }
  } finally {
    client.release();
  }
});

//ACTUALIZAR USUARIO
app.put("/updateuser/:id", async (req, res) => {
  const { id } = req.params;
  const {
    allow,
    username,
    firstName,
    lastName,
    password,
    email,
    active,
    updated_by
  } = req.body;

  const client = await pool.connect();

  try {
    const updateQuery = `
      UPDATE tbl_User
      SET
        allow = COALESCE($1, allow),
        username = COALESCE($2, username),
        first_name = COALESCE($3, first_name),
        last_name = COALESCE($4, last_name),
        password = COALESCE(crypt($5, gen_salt('bf')), password),
        email = COALESCE($6, email),
        active = COALESCE($7, active),
        updated_by = COALESCE($8, updated_by),
        updated_on = CURRENT_TIMESTAMP
      WHERE user_id = $9
      RETURNING user_id;
    `;

    const values = [
      allow,
      username,
      firstName || null,
      lastName || null,
      password || null,
      email,
      active,
      updated_by || null,
      id
    ];
    const result = await client.query(updateQuery, values);

    if (result.rowCount === 0) {
      return res.status(404).send("Usuario no encontrado");
    }

    console.log("Usuario actualizado con ID:", id);
    res.status(200).json({ message: "Usuario actualizado exitosamente", user_id: id });

  } catch (err) {
    console.error("Database error: ", err.message);

    if (err.code === '23505') {
      res.status(409).send("El nombre de usuario o correo electrónico ya existe");
    } else {
      res.status(500).send("Error al actualizar el usuario");
    }
  } finally {
    client.release();
  }
});


//OBTENER USUARIO
app.get("/getuser/:id", async (req, res) => {
  const { id } = req.params;

  const client = await pool.connect();

  try {
    const selectQuery = `
      SELECT user_id, allow, username, first_name, last_name, email, active, created_by, created_on, updated_by, updated_on
      FROM tbl_User
      WHERE user_id = $1;
    `;
    const result = await client.query(selectQuery, [id]);

    if (result.rows.length === 0) {
      return res.status(404).send("Usuario no encontrado");
    }
    res.status(200).json(result.rows[0]);

  } catch (err) {
    console.error("Database error: ", err.message);
    res.status(500).send("Error al buscar el usuario");
  } finally {
    client.release();
  }
});

// HISTORIAL DEL USUARIO

//CREAR HISTORIAL
app.post("/createuserhistory", async (req, res) => {
  const { user_id, allow, username, first_name, last_name, password, email, active, created_by } = req.body;

  const client = await pool.connect();

  try {
    const insertQuery = `
      INSERT INTO tbl_User_history (user_id, allow, username, first_name, last_name, password, email, active, created_by, created_on)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP)
      RETURNING history_number;
    `;

    const values = [
      user_id,
      allow || false,
      username,
      first_name,
      last_name,
      password,
      email,
      active || true,
      created_by || null
    ];

    const result = await client.query(insertQuery, values);

    res.status(201).json({ message: "Historial de usuario creado exitosamente", history_number: result.rows[0].history_number });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);

    if (err.code === '23505') {
      res.status(409).send("El nombre de usuario o el email ya existe");
    } else {
      res.status(500).send("Error al crear el historial de usuario");
    }
  } finally {
    client.release();
  }
});

//ACTUALIZAR HISTORIAL
app.put("/updateuserhistory/:id", async (req, res) => {
  const { id } = req.params;
  const { allow, username, first_name, last_name, password, email, active, updated_by } = req.body;

  const client = await pool.connect();

  try {
    const updateQuery = `
      UPDATE tbl_User_history
      SET
        allow = COALESCE($1, allow),
        username = COALESCE($2, username),
        first_name = COALESCE($3, first_name),
        last_name = COALESCE($4, last_name),
        password = COALESCE($5, password),
        email = COALESCE($6, email),
        active = COALESCE($7, active),
        updated_by = COALESCE($8, updated_by),
        updated_on = CURRENT_TIMESTAMP
      WHERE history_number = $9
      RETURNING history_number;
    `;

    const values = [
      allow,
      username,
      first_name,
      last_name,
      password,
      email,
      active,
      updated_by || null,
      id
    ];

    const result = await client.query(updateQuery, values);

    if (result.rowCount === 0) {
      return res.status(404).send("Historial de usuario no encontrado");
    }

    res.status(200).json({ message: "Historial de usuario actualizado exitosamente", history_number: id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);

    if (err.code === '23505') {
      res.status(409).send("El nombre de usuario o el email ya existe");
    } else {
      res.status(500).send("Error al actualizar el historial de usuario");
    }
  } finally {
    client.release();
  }
});

//OBTENER HISTORIAL POR ID
app.get("/getuserhistory/:id", async (req, res) => {
  const { id } = req.params;

  const client = await pool.connect();

  try {
    const selectQuery = `
      SELECT history_number, user_id, allow, username, first_name, last_name, email, active, created_by, created_on, updated_by, updated_on
      FROM tbl_User_history
      WHERE history_number = $1;
    `;

    const result = await client.query(selectQuery, [id]);

    if (result.rows.length === 0) {
      return res.status(404).send("Historial de usuario no encontrado");
    }

    res.status(200).json(result.rows[0]);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al buscar el historial de usuario");
  } finally {
    client.release();
  }
});

//OBTENER HISTORIALES
app.get("/getalluserhistories", async (req, res) => {
  const client = await pool.connect();

  try {
    const selectAllQuery = `
      SELECT history_number, user_id, allow, username, first_name, last_name, email, active, created_by, created_on, updated_by, updated_on
      FROM tbl_User_history;
    `;

    const result = await client.query(selectAllQuery);

    res.status(200).json(result.rows);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al obtener el historial de usuarios");
  } finally {
    client.release();
  }
});

//AUDITORIA DE USUARIO

//CREAR 
app.post("/createaudituser", async (req, res) => {
  const { user_id, effective_date, module_affected, resource_affected, change_code, change_description } = req.body;

  const client = await pool.connect();

  try {
    const insertQuery = `
      INSERT INTO tbl_Audit_User (user_id, effective_date, module_affected, resource_affected, change_code, change_description)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING history_id;
    `;

    const values = [
      user_id,
      effective_date || new Date(),
      module_affected,
      resource_affected,
      change_code,
      change_description
    ];

    const result = await client.query(insertQuery, values);

    res.status(201).json({ message: "Registro de auditoría creado exitosamente", history_id: result.rows[0].history_id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al crear el registro de auditoría");
  } finally {
    client.release();
  }
});

//ACTUALIZAR
app.put("/updateaudituser/:id", async (req, res) => {
  const { id } = req.params;
  const { effective_date, module_affected, resource_affected, change_code, change_description } = req.body;

  const client = await pool.connect();

  try {
    const updateQuery = `
      UPDATE tbl_Audit_User
      SET
        effective_date = COALESCE($1, effective_date),
        module_affected = COALESCE($2, module_affected),
        resource_affected = COALESCE($3, resource_affected),
        change_code = COALESCE($4, change_code),
        change_description = COALESCE($5, change_description)
      WHERE history_id = $6
      RETURNING history_id;
    `;

    const values = [
      effective_date,
      module_affected,
      resource_affected,
      change_code,
      change_description,
      id
    ];

    const result = await client.query(updateQuery, values);

    if (result.rowCount === 0) {
      return res.status(404).send("Registro de auditoría no encontrado");
    }

    res.status(200).json({ message: "Registro de auditoría actualizado exitosamente", history_id: id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al actualizar el registro de auditoría");
  } finally {
    client.release();
  }
});

//OBTENER POR ID
app.get("/getaudituser/:id", async (req, res) => {
  const { id } = req.params;

  const client = await pool.connect();

  try {
    const selectQuery = `
      SELECT history_id, user_id, effective_date, module_affected, resource_affected, change_code, change_description
      FROM tbl_Audit_User
      WHERE history_id = $1;
    `;

    const result = await client.query(selectQuery, [id]);

    if (result.rows.length === 0) {
      return res.status(404).send("Registro de auditoría no encontrado");
    }

    res.status(200).json(result.rows[0]);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al buscar el registro de auditoría");
  } finally {
    client.release();
  }
});

//OBTENER TODOS
app.get("/getallauditusers", async (req, res) => {
  const client = await pool.connect();

  try {
    const selectAllQuery = `
      SELECT history_id, user_id, effective_date, module_affected, resource_affected, change_code, change_description
      FROM tbl_Audit_User;
    `;

    const result = await client.query(selectAllQuery);

    res.status(200).json(result.rows);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al obtener los registros de auditoría");
  } finally {
    client.release();
  }
});

//MODULOS

//CREAR
app.post("/createmodule", async (req, res) => {
  const { module_id, app_id, name, active, created_by } = req.body;

  const client = await pool.connect();

  try {
    const insertQuery = `
      INSERT INTO tbl_Module (module_id, app_id, name, active, created_by)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING module_id;
    `;

    const values = [
      module_id,
      app_id,
      name,
      active !== undefined ? active : true,
      created_by || null
    ];

    const result = await client.query(insertQuery, values);

    res.status(201).json({ message: "Módulo creado exitosamente", module_id: result.rows[0].module_id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    if (err.code === '23503') {
      res.status(409).send("El ID de aplicación no existe");
    } else {
      res.status(500).send("Error al crear el módulo");
    }
  } finally {
    client.release();
  }
});

//ACTUALIZAR
app.put("/updatemodule/:id", async (req, res) => {
  const { id } = req.params;
  const { app_id, name, active, updated_by } = req.body;

  const client = await pool.connect();

  try {
    const updateQuery = `
      UPDATE tbl_Module
      SET
        app_id = COALESCE($1, app_id),
        name = COALESCE($2, name),
        active = COALESCE($3, active),
        updated_by = COALESCE($4, updated_by),
        updated_on = CURRENT_TIMESTAMP
      WHERE module_id = $5
      RETURNING module_id;
    `;

    const values = [app_id, name, active, updated_by || null, id];

    const result = await client.query(updateQuery, values);

    if (result.rowCount === 0) {
      return res.status(404).send("Módulo no encontrado");
    }

    res.status(200).json({ message: "Módulo actualizado exitosamente", module_id: id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al actualizar el módulo");
  } finally {
    client.release();
  }
});

//OBTENER POR ID
app.get("/getmodule/:id", async (req, res) => {
  const { id } = req.params;

  const client = await pool.connect();

  try {
    const selectQuery = `
      SELECT module_id, app_id, name, active, created_by, created_on, updated_by, updated_on
      FROM tbl_Module
      WHERE module_id = $1;
    `;

    const result = await client.query(selectQuery, [id]);

    if (result.rows.length === 0) {
      return res.status(404).send("Módulo no encontrado");
    }

    res.status(200).json(result.rows[0]);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al buscar el módulo");
  } finally {
    client.release();
  }
});

//OBTENER TODO
app.get("/getallmodules", async (req, res) => {
  const client = await pool.connect();

  try {
    const selectAllQuery = `
      SELECT module_id, app_id, name, active, created_by, created_on, updated_by, updated_on
      FROM tbl_Module;
    `;

    const result = await client.query(selectAllQuery);

    res.status(200).json(result.rows);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al obtener los módulos");
  } finally {
    client.release();
  }
});

//ROLES

//CREAR ROL
app.post("/createrole", async (req, res) => {
  const { role_id, name, active, created_by } = req.body;

  const client = await pool.connect();

  try {
    const insertQuery = `
      INSERT INTO tbl_Role (role_id, name, active, created_by)
      VALUES ($1, $2, $3, $4)
      RETURNING role_id;
    `;

    const values = [role_id, name, active || true, created_by || null];

    const result = await client.query(insertQuery, values);

    res.status(201).json({ message: "Rol creado exitosamente", role_id: result.rows[0].role_id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);

    if (err.code === '23505') {
      res.status(409).send("El nombre del rol ya existe");
    } else {
      res.status(500).send("Error al crear el rol");
    }
  } finally {
    client.release();
  }
});

//ACTUALIZAR ROL
app.put("/updaterole/:id", async (req, res) => {
  const { id } = req.params;
  const { name, active, updated_by } = req.body;

  const client = await pool.connect();

  try {
    const updateQuery = `
      UPDATE tbl_Role
      SET
        name = COALESCE($1, name),
        active = COALESCE($2, active),
        updated_by = COALESCE($3, updated_by),
        updated_on = CURRENT_TIMESTAMP
      WHERE role_id = $4
      RETURNING role_id;
    `;

    const values = [name, active, updated_by || null, id];

    const result = await client.query(updateQuery, values);

    if (result.rowCount === 0) {
      return res.status(404).send("Rol no encontrado");
    }

    res.status(200).json({ message: "Rol actualizado exitosamente", role_id: id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);

    if (err.code === '23505') {
      res.status(409).send("El nombre del rol ya existe");
    } else {
      res.status(500).send("Error al actualizar el rol");
    }
  } finally {
    client.release();
  }
});

//OBTENER ROL
app.get("/getrole/:id", async (req, res) => {
  const { id } = req.params;

  const client = await pool.connect();

  try {
    const selectQuery = `
      SELECT role_id, name, active, created_by, created_on, updated_by, updated_on
      FROM tbl_Role
      WHERE role_id = $1;
    `;

    const result = await client.query(selectQuery, [id]);

    if (result.rows.length === 0) {
      return res.status(404).send("Rol no encontrado");
    }

    res.status(200).json(result.rows[0]);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al buscar el rol");
  } finally {
    client.release();
  }
});


//OBTENER TODOS ROLES
app.get("/getallroles", async (req, res) => {
  const client = await pool.connect();

  try {
    const selectAllQuery = `
      SELECT role_id, name, active, created_by, created_on, updated_by, updated_on
      FROM tbl_Role;
    `;

    const result = await client.query(selectAllQuery);

    res.status(200).json(result.rows);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al obtener los roles");
  } finally {
    client.release();
  }
});

//PERMISOS

//CREAR PERMISO
app.post("/createpermission", async (req, res) => {
  const { permission_id, type, name, active, created_by } = req.body;

  const client = await pool.connect();

  try {
    const insertQuery = `
      INSERT INTO tbl_Permission (permission_id, type, name, active, created_by)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING permission_id;
    `;

    const values = [permission_id, type, name, active || true, created_by || null];

    const result = await client.query(insertQuery, values);

    res.status(201).json({ message: "Permiso creado exitosamente", permission_id: result.rows[0].permission_id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);

    if (err.code === '23505') {
      res.status(409).send("El nombre del permiso ya existe");
    } else {
      res.status(500).send("Error al crear el permiso");
    }
  } finally {
    client.release();
  }
});

//ACTUALIZAR PERMISO
app.put("/updatepermission/:id", async (req, res) => {
  const { id } = req.params;
  const { type, name, active, updated_by } = req.body;

  const client = await pool.connect();

  try {
    const updateQuery = `
      UPDATE tbl_Permission
      SET
        type = COALESCE($1, type),
        name = COALESCE($2, name),
        active = COALESCE($3, active),
        updated_by = COALESCE($4, updated_by),
        updated_on = CURRENT_TIMESTAMP
      WHERE permission_id = $5
      RETURNING permission_id;
    `;

    const values = [type, name, active, updated_by || null, id];

    const result = await client.query(updateQuery, values);

    if (result.rowCount === 0) {
      return res.status(404).send("Permiso no encontrado");
    }

    res.status(200).json({ message: "Permiso actualizado exitosamente", permission_id: id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);

    if (err.code === '23505') {
      res.status(409).send("El nombre del permiso ya existe");
    } else {
      res.status(500).send("Error al actualizar el permiso");
    }
  } finally {
    client.release();
  }
});

//OBTENER PERMISO
app.get("/getpermission/:id", async (req, res) => {
  const { id } = req.params;

  const client = await pool.connect();

  try {
    const selectQuery = `
      SELECT permission_id, type, name, active, created_by, created_on, updated_by, updated_on
      FROM tbl_Permission
      WHERE permission_id = $1;
    `;

    const result = await client.query(selectQuery, [id]);

    if (result.rows.length === 0) {
      return res.status(404).send("Permiso no encontrado");
    }

    res.status(200).json(result.rows[0]);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al buscar el permiso");
  } finally {
    client.release();
  }
});

//OBTENER TODO
app.get("/getallpermissions", async (req, res) => {
  const client = await pool.connect();

  try {
    const selectAllQuery = `
      SELECT permission_id, type, name, active, created_by, created_on, updated_by, updated_on
      FROM tbl_Permission;
    `;

    const result = await client.query(selectAllQuery);

    res.status(200).json(result.rows);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al obtener los permisos");
  } finally {
    client.release();
  }
});

//RESOURCE

//CREAR 
app.post("/createresource", async (req, res) => {
  const { resource_id, name, active, created_by } = req.body;

  const client = await pool.connect();

  try {
    const insertQuery = `
      INSERT INTO tbl_Resource (resource_id, name, active, created_by)
      VALUES ($1, $2, $3, $4)
      RETURNING resource_id;
    `;

    const values = [
      resource_id,
      name,
      active !== undefined ? active : true,
      created_by || null
    ];

    const result = await client.query(insertQuery, values);

    res.status(201).json({ message: "Recurso creado exitosamente", resource_id: result.rows[0].resource_id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    if (err.code === '23505') {
      res.status(409).send("El nombre del recurso ya existe");
    } else {
      res.status(500).send("Error al crear el recurso");
    }
  } finally {
    client.release();
  }
});

//ACTUALIZAR
app.put("/updateresource/:id", async (req, res) => {
  const { id } = req.params;
  const { name, active, updated_by } = req.body;

  const client = await pool.connect();

  try {
    const updateQuery = `
      UPDATE tbl_Resource
      SET
        name = COALESCE($1, name),
        active = COALESCE($2, active),
        updated_by = COALESCE($3, updated_by),
        updated_on = CURRENT_TIMESTAMP
      WHERE resource_id = $4
      RETURNING resource_id;
    `;

    const values = [name, active, updated_by || null, id];

    const result = await client.query(updateQuery, values);

    if (result.rowCount === 0) {
      return res.status(404).send("Recurso no encontrado");
    }

    res.status(200).json({ message: "Recurso actualizado exitosamente", resource_id: id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al actualizar el recurso");
  } finally {
    client.release();
  }
});

//OBTENER
app.get("/getresource/:id", async (req, res) => {
  const { id } = req.params;

  const client = await pool.connect();

  try {
    const selectQuery = `
      SELECT resource_id, name, active, created_by, created_on, updated_by, updated_on
      FROM tbl_Resource
      WHERE resource_id = $1;
    `;

    const result = await client.query(selectQuery, [id]);

    if (result.rows.length === 0) {
      return res.status(404).send("Recurso no encontrado");
    }

    res.status(200).json(result.rows[0]);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al buscar el recurso");
  } finally {
    client.release();
  }
});

//OBTENER TODO
app.get("/getallresources", async (req, res) => {
  const client = await pool.connect();

  try {
    const selectAllQuery = `
      SELECT resource_id, name, active, created_by, created_on, updated_by, updated_on
      FROM tbl_Resource;
    `;

    const result = await client.query(selectAllQuery);

    res.status(200).json(result.rows);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al obtener los recursos");
  } finally {
    client.release();
  }
});


//USER APP

//CREAR 
app.post("/createuserapp", async (req, res) => {
  const { user_app_id, user_id, app_id, created_by } = req.body;

  const client = await pool.connect();

  try {
    const insertQuery = `
      INSERT INTO tbl_User_App (user_app_id, user_id, app_id, created_by)
      VALUES ($1, $2, $3, $4)
      RETURNING user_app_id;
    `;

    const values = [
      user_app_id,
      user_id,
      app_id,
      created_by || null
    ];

    const result = await client.query(insertQuery, values);

    res.status(201).json({ message: "Usuario-App creado exitosamente", user_app_id: result.rows[0].user_app_id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al crear el Usuario-App");
  } finally {
    client.release();
  }
});

//ACTUALIZAR
app.put("/updateuserapp/:id", async (req, res) => {
  const { id } = req.params;
  const { user_id, app_id, updated_by } = req.body;

  const client = await pool.connect();

  try {
    const updateQuery = `
      UPDATE tbl_User_App
      SET
        user_id = COALESCE($1, user_id),
        app_id = COALESCE($2, app_id),
        updated_by = COALESCE($3, updated_by),
        updated_on = CURRENT_TIMESTAMP
      WHERE user_app_id = $4
      RETURNING user_app_id;
    `;

    const values = [user_id, app_id, updated_by || null, id];

    const result = await client.query(updateQuery, values);

    if (result.rowCount === 0) {
      return res.status(404).send("Usuario-App no encontrado");
    }

    res.status(200).json({ message: "Usuario-App actualizado exitosamente", user_app_id: id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al actualizar el Usuario-App");
  } finally {
    client.release();
  }
});

//OBTENER
app.get("/getuserapp/:id", async (req, res) => {
  const { id } = req.params;

  const client = await pool.connect();

  try {
    const selectQuery = `
      SELECT user_app_id, user_id, app_id, created_by, created_on, updated_by, updated_on
      FROM tbl_User_App
      WHERE user_app_id = $1;
    `;

    const result = await client.query(selectQuery, [id]);

    if (result.rows.length === 0) {
      return res.status(404).send("Usuario-App no encontrado");
    }

    res.status(200).json(result.rows[0]);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al buscar el Usuario-App");
  } finally {
    client.release();
  }
});

//OBTENER TODO
app.get("/getalluserapps", async (req, res) => {
  const client = await pool.connect();

  try {
    const selectAllQuery = `
      SELECT user_app_id, user_id, app_id, created_by, created_on, updated_by, updated_on
      FROM tbl_User_App;
    `;

    const result = await client.query(selectAllQuery);

    res.status(200).json(result.rows);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al obtener los Usuario-App");
  } finally {
    client.release();
  }
});


//USER ROLE

//CREAR 
app.post("/createuserrole", async (req, res) => {
  const { user_role_id, user_id, role_id, created_by } = req.body;

  const client = await pool.connect();

  try {
    const insertQuery = `
      INSERT INTO tbl_User_Role (user_role_id, user_id, role_id, created_by)
      VALUES ($1, $2, $3, $4)
      RETURNING user_role_id;
    `;

    const values = [
      user_role_id,
      user_id,
      role_id,
      created_by || null
    ];

    const result = await client.query(insertQuery, values);

    res.status(201).json({ message: "Usuario-Rol creado exitosamente", user_role_id: result.rows[0].user_role_id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al crear el Usuario-Rol");
  } finally {
    client.release();
  }
});

//ACTUALIZAR
app.put("/updateuserrole/:id", async (req, res) => {
  const { id } = req.params;
  const { user_id, role_id, updated_by } = req.body;

  const client = await pool.connect();

  try {
    const updateQuery = `
      UPDATE tbl_User_Role
      SET
        user_id = COALESCE($1, user_id),
        role_id = COALESCE($2, role_id),
        updated_by = COALESCE($3, updated_by),
        updated_on = CURRENT_TIMESTAMP
      WHERE user_role_id = $4
      RETURNING user_role_id;
    `;

    const values = [user_id, role_id, updated_by || null, id];

    const result = await client.query(updateQuery, values);

    if (result.rowCount === 0) {
      return res.status(404).send("Usuario-Rol no encontrado");
    }

    res.status(200).json({ message: "Usuario-Rol actualizado exitosamente", user_role_id: id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al actualizar el Usuario-Rol");
  } finally {
    client.release();
  }
});

//OBTENER
app.get("/getuserrole/:id", async (req, res) => {
  const { id } = req.params;

  const client = await pool.connect();

  try {
    const selectQuery = `
      SELECT user_role_id, user_id, role_id, created_by, created_on, updated_by, updated_on
      FROM tbl_User_Role
      WHERE user_role_id = $1;
    `;

    const result = await client.query(selectQuery, [id]);

    if (result.rows.length === 0) {
      return res.status(404).send("Usuario-Rol no encontrado");
    }

    res.status(200).json(result.rows[0]);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al buscar el Usuario-Rol");
  } finally {
    client.release();
  }
});

//OBTENER TODO
app.get("/getalluserroles", async (req, res) => {
  const client = await pool.connect();

  try {
    const selectAllQuery = `
      SELECT user_role_id, user_id, role_id, created_by, created_on, updated_by, updated_on
      FROM tbl_User_Role;
    `;

    const result = await client.query(selectAllQuery);

    res.status(200).json(result.rows);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al obtener los Usuario-Rol");
  } finally {
    client.release();
  }
});


//ROLE ROLE

//CREAR 
app.post("/createrolerole", async (req, res) => {
  const { role_role_id, parent_role_id, child_role_id, created_by } = req.body;

  const client = await pool.connect();

  try {
    const insertQuery = `
      INSERT INTO tbl_Role_Role (role_role_id, parent_role_id, child_role_id, created_by)
      VALUES ($1, $2, $3, $4)
      RETURNING role_role_id;
    `;

    const values = [
      role_role_id,
      parent_role_id,
      child_role_id,
      created_by || null
    ];

    const result = await client.query(insertQuery, values);

    res.status(201).json({ message: "Relación Rol-Rol creada exitosamente", role_role_id: result.rows[0].role_role_id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al crear la Relación Rol-Rol");
  } finally {
    client.release();
  }
});

//ACTUALIZAR
app.put("/updaterolerole/:id", async (req, res) => {
  const { id } = req.params;
  const { parent_role_id, child_role_id, updated_by } = req.body;

  const client = await pool.connect();

  try {
    const updateQuery = `
      UPDATE tbl_Role_Role
      SET
        parent_role_id = COALESCE($1, parent_role_id),
        child_role_id = COALESCE($2, child_role_id),
        updated_by = COALESCE($3, updated_by),
        updated_on = CURRENT_TIMESTAMP
      WHERE role_role_id = $4
      RETURNING role_role_id;
    `;

    const values = [parent_role_id, child_role_id, updated_by || null, id];

    const result = await client.query(updateQuery, values);

    if (result.rowCount === 0) {
      return res.status(404).send("Relación Rol-Rol no encontrada");
    }

    res.status(200).json({ message: "Relación Rol-Rol actualizada exitosamente", role_role_id: id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al actualizar la Relación Rol-Rol");
  } finally {
    client.release();
  }
});

//OBTENER
app.get("/getrolerole/:id", async (req, res) => {
  const { id } = req.params;

  const client = await pool.connect();

  try {
    const selectQuery = `
      SELECT role_role_id, parent_role_id, child_role_id, created_by, created_on, updated_by, updated_on
      FROM tbl_Role_Role
      WHERE role_role_id = $1;
    `;

    const result = await client.query(selectQuery, [id]);

    if (result.rows.length === 0) {
      return res.status(404).send("Relación Rol-Rol no encontrada");
    }

    res.status(200).json(result.rows[0]);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al buscar la Relación Rol-Rol");
  } finally {
    client.release();
  }
});

//OBTENER TODO
app.get("/getallroleroles", async (req, res) => {
  const client = await pool.connect();

  try {
    const selectAllQuery = `
      SELECT role_role_id, parent_role_id, child_role_id, created_by, created_on, updated_by, updated_on
      FROM tbl_Role_Role;
    `;

    const result = await client.query(selectAllQuery);

    res.status(200).json(result.rows);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al obtener las Relaciones Rol-Rol");
  } finally {
    client.release();
  }
});


//ROLE PERMISION

//CREAR 
app.post("/createrolepermission", async (req, res) => {
  const { role_permission_id, role_id, permission_id, created_by } = req.body;

  const client = await pool.connect();

  try {
    const insertQuery = `
      INSERT INTO tbl_Role_Permission (role_permission_id, role_id, permission_id, created_by)
      VALUES ($1, $2, $3, $4)
      RETURNING role_permission_id;
    `;

    const values = [
      role_permission_id,
      role_id,
      permission_id,
      created_by || null
    ];

    const result = await client.query(insertQuery, values);

    res.status(201).json({ message: "Relación Rol-Permiso creada exitosamente", role_permission_id: result.rows[0].role_permission_id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al crear la Relación Rol-Permiso");
  } finally {
    client.release();
  }
});

//ACTUALIZAR
app.put("/updaterolepermission/:id", async (req, res) => {
  const { id } = req.params;
  const { role_id, permission_id, updated_by } = req.body;

  const client = await pool.connect();

  try {
    const updateQuery = `
      UPDATE tbl_Role_Permission
      SET
        role_id = COALESCE($1, role_id),
        permission_id = COALESCE($2, permission_id),
        updated_by = COALESCE($3, updated_by),
        updated_on = CURRENT_TIMESTAMP
      WHERE role_permission_id = $4
      RETURNING role_permission_id;
    `;

    const values = [role_id, permission_id, updated_by || null, id];

    const result = await client.query(updateQuery, values);

    if (result.rowCount === 0) {
      return res.status(404).send("Relación Rol-Permiso no encontrada");
    }

    res.status(200).json({ message: "Relación Rol-Permiso actualizada exitosamente", role_permission_id: id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al actualizar la Relación Rol-Permiso");
  } finally {
    client.release();
  }
});

//OBTENER
app.get("/getrolepermission/:id", async (req, res) => {
  const { id } = req.params;

  const client = await pool.connect();

  try {
    const selectQuery = `
      SELECT role_permission_id, role_id, permission_id, created_by, created_on, updated_by, updated_on
      FROM tbl_Role_Permission
      WHERE role_permission_id = $1;
    `;

    const result = await client.query(selectQuery, [id]);

    if (result.rows.length === 0) {
      return res.status(404).send("Relación Rol-Permiso no encontrada");
    }

    res.status(200).json(result.rows[0]);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al buscar la Relación Rol-Permiso");
  } finally {
    client.release();
  }
});

//OBTENER TODO
app.get("/getallrolepermissions", async (req, res) => {
  const client = await pool.connect();

  try {
    const selectAllQuery = `
      SELECT role_permission_id, role_id, permission_id, created_by, created_on, updated_by, updated_on
      FROM tbl_Role_Permission;
    `;

    const result = await client.query(selectAllQuery);

    res.status(200).json(result.rows);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al obtener las Relaciones Rol-Permiso");
  } finally {
    client.release();
  }
});


//PERMISION RESOURCE

//CREAR 
app.post("/createpermissionresource", async (req, res) => {
  const { permission_resource_id, permission_id, resource_id, created_by } = req.body;

  const client = await pool.connect();

  try {
    const insertQuery = `
      INSERT INTO tbl_Permission_Resource (permission_resource_id, permission_id, resource_id, created_by)
      VALUES ($1, $2, $3, $4)
      RETURNING permission_resource_id;
    `;

    const values = [
      permission_resource_id,
      permission_id,
      resource_id,
      created_by || null
    ];

    const result = await client.query(insertQuery, values);

    res.status(201).json({ message: "Relación Permiso-Recurso creada exitosamente", permission_resource_id: result.rows[0].permission_resource_id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al crear la Relación Permiso-Recurso");
  } finally {
    client.release();
  }
});

//ACTUALIZAR
app.put("/updatepermissionresource/:id", async (req, res) => {
  const { id } = req.params;
  const { permission_id, resource_id, updated_by } = req.body;

  const client = await pool.connect();

  try {
    const updateQuery = `
      UPDATE tbl_Permission_Resource
      SET
        permission_id = COALESCE($1, permission_id),
        resource_id = COALESCE($2, resource_id),
        updated_by = COALESCE($3, updated_by),
        updated_on = CURRENT_TIMESTAMP
      WHERE permission_resource_id = $4
      RETURNING permission_resource_id;
    `;

    const values = [permission_id, resource_id, updated_by || null, id];

    const result = await client.query(updateQuery, values);

    if (result.rowCount === 0) {
      return res.status(404).send("Relación Permiso-Recurso no encontrada");
    }

    res.status(200).json({ message: "Relación Permiso-Recurso actualizada exitosamente", permission_resource_id: id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al actualizar la Relación Permiso-Recurso");
  } finally {
    client.release();
  }
});

//OBTENER
app.get("/getpermissionresource/:id", async (req, res) => {
  const { id } = req.params;

  const client = await pool.connect();

  try {
    const selectQuery = `
      SELECT permission_resource_id, permission_id, resource_id, created_by, created_on, updated_by, updated_on
      FROM tbl_Permission_Resource
      WHERE permission_resource_id = $1;
    `;

    const result = await client.query(selectQuery, [id]);

    if (result.rows.length === 0) {
      return res.status(404).send("Relación Permiso-Recurso no encontrada");
    }

    res.status(200).json(result.rows[0]);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al buscar la Relación Permiso-Recurso");
  } finally {
    client.release();
  }
});

//OBTENER TODO
app.get("/getallpermissionresources", async (req, res) => {
  const client = await pool.connect();

  try {
    const selectAllQuery = `
      SELECT permission_resource_id, permission_id, resource_id, created_by, created_on, updated_by, updated_on
      FROM tbl_Permission_Resource;
    `;

    const result = await client.query(selectAllQuery);

    res.status(200).json(result.rows);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al obtener las Relaciones Permiso-Recurso");
  } finally {
    client.release();
  }
});

//MODULE RESOURCE

//CREAR 
app.post("/createmoduleresource", async (req, res) => {
  const { module_resource_id, module_id, resource_id, created_by } = req.body;

  const client = await pool.connect();

  try {
    const insertQuery = `
      INSERT INTO tbl_Module_Resource (module_resource_id, module_id, resource_id, created_by)
      VALUES ($1, $2, $3, $4)
      RETURNING module_resource_id;
    `;

    const values = [
      module_resource_id,
      module_id,
      resource_id,
      created_by || null
    ];

    const result = await client.query(insertQuery, values);

    res.status(201).json({ message: "Relación Módulo-Recurso creada exitosamente", module_resource_id: result.rows[0].module_resource_id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al crear la Relación Módulo-Recurso");
  } finally {
    client.release();
  }
});

//ACTUALIZAR
app.put("/updatemoduleresource/:id", async (req, res) => {
  const { id } = req.params;
  const { module_id, resource_id, updated_by } = req.body;

  const client = await pool.connect();

  try {
    const updateQuery = `
      UPDATE tbl_Module_Resource
      SET
        module_id = COALESCE($1, module_id),
        resource_id = COALESCE($2, resource_id),
        updated_by = COALESCE($3, updated_by),
        updated_on = CURRENT_TIMESTAMP
      WHERE module_resource_id = $4
      RETURNING module_resource_id;
    `;

    const values = [module_id, resource_id, updated_by || null, id];

    const result = await client.query(updateQuery, values);

    if (result.rowCount === 0) {
      return res.status(404).send("Relación Módulo-Recurso no encontrada");
    }

    res.status(200).json({ message: "Relación Módulo-Recurso actualizada exitosamente", module_resource_id: id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al actualizar la Relación Módulo-Recurso");
  } finally {
    client.release();
  }
});

//OBTENER
app.get("/getmoduleresource/:id", async (req, res) => {
  const { id } = req.params;

  const client = await pool.connect();

  try {
    const selectQuery = `
      SELECT module_resource_id, module_id, resource_id, created_by, created_on, updated_by, updated_on
      FROM tbl_Module_Resource
      WHERE module_resource_id = $1;
    `;

    const result = await client.query(selectQuery, [id]);

    if (result.rows.length === 0) {
      return res.status(404).send("Relación Módulo-Recurso no encontrada");
    }

    res.status(200).json(result.rows[0]);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al buscar la Relación Módulo-Recurso");
  } finally {
    client.release();
  }
});

//OBTENER TODO
app.get("/getallmoduleresources", async (req, res) => {
  const client = await pool.connect();

  try {
    const selectAllQuery = `
      SELECT module_resource_id, module_id, resource_id, created_by, created_on, updated_by, updated_on
      FROM tbl_Module_Resource;
    `;

    const result = await client.query(selectAllQuery);

    res.status(200).json(result.rows);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al obtener las Relaciones Módulo-Recurso");
  } finally {
    client.release();
  }
});


//SESSIONS

//CREAR 
app.post("/createsession", async (req, res) => {
  const { user_id, session_from, session_duration, created_by } = req.body;

  const client = await pool.connect();

  try {
    const insertQuery = `
      INSERT INTO tbl_Sessions (user_id, session_from, session_duration, created_by)
      VALUES ($1, $2, $3, $4)
      RETURNING session_id;
    `;

    const values = [
      user_id,
      session_from || null,
      session_duration || null,
      created_by || null
    ];

    const result = await client.query(insertQuery, values);

    res.status(201).json({ message: "Sesión creada exitosamente", session_id: result.rows[0].session_id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al crear la sesión");
  } finally {
    client.release();
  }
});

//ACTUALIZAR
app.put("/updatesession/:id", async (req, res) => {
  const { id } = req.params;
  const { user_id, session_from, session_duration, updated_by } = req.body;

  const client = await pool.connect();

  try {
    const updateQuery = `
      UPDATE tbl_Sessions
      SET
        user_id = COALESCE($1, user_id),
        session_from = COALESCE($2, session_from),
        session_duration = COALESCE($3, session_duration),
        updated_by = COALESCE($4, updated_by),
        updated_on = CURRENT_TIMESTAMP
      WHERE session_id = $5
      RETURNING session_id;
    `;

    const values = [user_id, session_from, session_duration, updated_by || null, id];

    const result = await client.query(updateQuery, values);

    if (result.rowCount === 0) {
      return res.status(404).send("Sesión no encontrada");
    }

    res.status(200).json({ message: "Sesión actualizada exitosamente", session_id: id });

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al actualizar la sesión");
  } finally {
    client.release();
  }
});

//OBTENER
app.get("/getsession/:id", async (req, res) => {
  const { id } = req.params;

  const client = await pool.connect();

  try {
    const selectQuery = `
      SELECT session_id, user_id, session_at, session_from, session_duration, created_by, created_on, updated_by, updated_on
      FROM tbl_Sessions
      WHERE session_id = $1;
    `;

    const result = await client.query(selectQuery, [id]);

    if (result.rows.length === 0) {
      return res.status(404).send("Sesión no encontrada");
    }

    res.status(200).json(result.rows[0]);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al buscar la sesión");
  } finally {
    client.release();
  }
});

//OBTENER TODO
app.get("/getallsessions", async (req, res) => {
  const client = await pool.connect();

  try {
    const selectAllQuery = `
      SELECT session_id, user_id, session_at, session_from, session_duration, created_by, created_on, updated_by, updated_on
      FROM tbl_Sessions;
    `;

    const result = await client.query(selectAllQuery);

    res.status(200).json(result.rows);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al obtener las sesiones");
  } finally {
    client.release();
  }
});




//vw_UserPermissions 

//OBTENER
app.get("/getuserpermissions", async (req, res) => {
  const client = await pool.connect();

  try {
    const selectQuery = `
      SELECT 
          user_id,
          username,
          first_name,
          last_name,
          app_name,
          module_name,
          resource_name,
          permission_name,
          permission_type,
          role_name
      FROM vw_UserPermissions;
    `;

    const result = await client.query(selectQuery);

    res.status(200).json(result.rows);

  } catch (err) {
    console.error("Error en la base de datos: ", err.message);
    res.status(500).send("Error al obtener los permisos de los usuarios");
  } finally {
    client.release();
  }
});


const port = process.env.PORT || 3002;

app.listen(port, () => {
  console.log(`gatemaster listening on port ${port}`);
});