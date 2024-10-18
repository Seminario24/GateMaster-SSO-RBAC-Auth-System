import express from "express";
import dotenv from "dotenv";
import redis from "ioredis";
import axios from "axios";
import pkg from 'pg';
const { Pool } = pkg;


dotenv.config();

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

const app = express();
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

//USUARIO

//ALMACENAR USUARIO
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

  // Conexión a la base de datos
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

    // Retornar el usuario encontrado
    res.status(200).json(result.rows[0]);

  } catch (err) {
    console.error("Database error: ", err.message);
    res.status(500).send("Error al buscar el usuario");
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

//OBTENER TODOS PERMISOS
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

const port = process.env.PORT || 3002;

app.listen(port, () => {
  console.log(`gatemaster listening on port ${port}`);
});
