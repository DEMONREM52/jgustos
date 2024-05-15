// Importar dependencias
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const bodyParser = require("body-parser");
const mysql = require("mysql");
const path = require("path");
const bcrypt = require("bcrypt");
const { render } = require("ejs");
// Configuración de Express
const app = express();
const port = process.env.PORT || 80;
const DB_HOST = process.env.DB_HOST || "gustos-dbgustos";
const DB_USER = process.env.DB_USER || "mysql";
const DB_PASSWORD = process.env.DB_PASSWORD || "313cb770678d07260125";
const DB_NAME = process.env.DB_NAME || "gustos";
const DB_PORT = process.env.DB_PORT || "3306";

app.use(
  session({
    secret: "secret-key", // Cambia esto por una cadena de caracteres aleatoria y segura
    resave: false,
    saveUninitialized: true,
  })
);

// Agregar middleware para analizar el cuerpo de las peticiones como JSON
app.use(bodyParser.json());
app.use((req, res, next) => {
  res.locals.usuario = req.user; // Pasar req.user a res.locals para que esté disponible en todas las plantillas
  next();
});
app.use(bodyParser.urlencoded({ extended: true }));

app.use(passport.initialize());
app.use(passport.session());

// Configuración de la base de datos
const db = mysql.createConnection({
  host: DB_HOST,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
});

// Conexión a la base de datos
db.connect((err) => {
  if (err) {
    throw err;
  }
  console.log("Conexión exitosa a la base de datos MySQL");
});

// Configurar EJS como motor de plantillas
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Rutas
app.get("/", (req, res) => {
  // Obtener datos de vehículos de la base de datos
  db.query("SELECT * FROM restaurantes", (err, results) => {
    if (err) {
      throw err;
    }
    // Obtener el usuario de la sesión
    const usuario = req.session.usuario;

    // Renderizar la vista index.ejs y pasar los datos de los vehículos y el usuario
    res.render("index", { usuario: usuario, restaurantes: results });
  });
});

app.get("/catalogo", (req, res) => {
  // Obtener datos de vehículos y usuarios de la base de datos en paralelo
  db.query("SELECT * FROM restaurantes", (errrestaurantes, resultadosrestaurantes) => {
    if (errrestaurantes) {
      res.status(500).send("Error interno del servidor al obtener vehículos");
    } else {
      db.query("SELECT * FROM usuarios", (errUsuarios, resultadosUsuarios) => {
        if (errUsuarios) {
          res
            .status(500)
            .send("Error interno del servidor al obtener usuarios");
        } else {
          // Obtener el usuario de la sesión
          const usuario = req.session.usuario;

          // Renderizar la vista de vehículos y pasar los datos de vehículos y usuarios
          res.render("catalogo", {
            restaurantes: resultadosrestaurantes,
            usuarios: resultadosUsuarios,
            usuario: usuario,
          });
        }
      });
    }
  });
});

app.get("/editar-usuario/:id", (req, res) => {
  const usuarioId = req.params.id;
  // Obtener información del usuario con el ID proporcionado
  db.query(
    "SELECT * FROM usuarios WHERE id = ?",
    [usuarioId],
    (err, result) => {
      if (err) {
        console.error("Error al obtener información del usuario:", err);
        res.status(500).send("Error interno del servidor");
      } else {
        // Renderizar el formulario de edición de usuario y pasar los datos del usuario
        res.render("editar-usuario", {
          usuario: result[0],
          isAdmin: req.session.usuario.rol === "superadmin", // Verificar si el usuario es superadmin
        });
      }
    }
  );
});

app.post("/editar-usuario/:id", (req, res) => {
  const usuarioId = req.params.id;
  const { nombre: nuevoNombre, email, contraseña, rol } = req.body;

  // Obtener el nombre actual del usuario
  db.query(
    "SELECT nombre FROM usuarios WHERE id = ?",
    [usuarioId],
    (err, resultado) => {
      if (err) {
        console.error("Error al obtener el nombre del usuario:", err);
        res.status(500).send("Error interno del servidor");
      } else {
        const nombreAnterior = resultado[0].nombre;

        // Verificar si el nuevo nombre ya está en uso
        db.query(
          "SELECT COUNT(*) AS count FROM usuarios WHERE nombre = ? AND id != ?",
          [nuevoNombre, usuarioId],
          (err, resultado) => {
            if (err) {
              console.error("Error al verificar el nombre de usuario:", err);
              res.status(500).send("Error interno del servidor");
            } else {
              const count = resultado[0].count;

              if (count > 0) {
                // Si el nombre ya está en uso, mostrar un mensaje de alerta
                res.send(`
                                  <script>
                                      alert("El nombre de usuario ya está en uso. Por favor, elige otro nombre.");
                                      window.location.href = "/editar-usuario/${usuarioId}";
                                  </script>
                              `);
              } else {
                // Actualizar el nombre del usuario en la tabla de usuarios
                db.query(
                  "UPDATE usuarios SET nombre = ?, email = ?, contraseña = ?, rol = ? WHERE id = ?",
                  [nuevoNombre, email, contraseña, rol, usuarioId],
                  (err, resultado) => {
                    if (err) {
                      console.error("Error al actualizar el usuario:", err);
                      res.status(500).send("Error interno del servidor");
                    } else {
                      // Actualizar el nombre en la tabla de vehículos
                      db.query(
                        "UPDATE restaurantes SET usuarioAgrego = ? WHERE usuarioAgrego = ?",
                        [nuevoNombre, nombreAnterior],
                        (err, resultado) => {
                          if (err) {
                            console.error(
                              "Error al actualizar el nombre en la tabla de vehículos:",
                              err
                            );
                            res.status(500).send("Error interno del servidor");
                          } else {
                            console.log(
                              "Usuario y vehículos actualizados correctamente"
                            );
                            // Redireccionar a la página de vehículos después de editar el usuario
                            res.redirect("/catalogo");
                          }
                        }
                      );
                    }
                  }
                );
              }
            }
          }
        );
      }
    }
  );
});

app.post("/borrar-usuario/:id", (req, res) => {
  const usuarioId = req.params.id;

  // Obtener el nombre del usuario para mostrar en el mensaje de confirmación
  db.query(
    "SELECT nombre FROM usuarios WHERE id = ?",
    [usuarioId],
    (err, resultado) => {
      if (err) {
        console.error("Error al buscar el usuario:", err);
        res.status(500).send("Error interno del servidor");
      } else {
        const nombreUsuario = resultado[0].nombre;

        // Mostrar mensaje de confirmación utilizando JavaScript
        res.send(`
          <script>
            var confirmacion = confirm("¿Estás seguro de eliminar a ${nombreUsuario}?");

            if (confirmacion) {
              window.location.href = "/confirmar-eliminacion/${usuarioId}";
            } else {
              window.location.href = "/usuario";
            }
          </script>
        `);
      }
    }
  );
});

app.get("/confirmar-eliminacion/:id", (req, res) => {
  const usuarioId = req.params.id;

  // Obtener el nombre del usuario que se está eliminando
  db.query(
    "SELECT nombre FROM usuarios WHERE id = ?",
    [usuarioId],
    (err, resultado) => {
      if (err) {
        console.error("Error al obtener el nombre del usuario:", err);
        res.status(500).send("Error interno del servidor");
      } else {
        const nombreUsuario = resultado[0].nombre;

        // Eliminar todos los vehículos asociados al usuario
        db.query(
          "DELETE FROM restaurantes WHERE usuarioAgrego = ?",
          [nombreUsuario],
          (err, resultado) => {
            if (err) {
              console.error(
                "Error al eliminar los vehículos asociados al usuario:",
                err
              );
              res.status(500).send("Error interno del servidor");
            } else {
              console.log(
                "Vehículos asociados al usuario eliminados correctamente"
              );

              // Ahora procedemos a eliminar al usuario
              db.query(
                "DELETE FROM usuarios WHERE id = ?",
                [usuarioId],
                (err, resultado) => {
                  if (err) {
                    console.error("Error al eliminar el usuario:", err);
                    res.status(500).send("Error interno del servidor");
                  } else {
                    console.log("Usuario eliminado correctamente");
                    res.redirect("/catalogo");
                  }
                }
              );
            }
          }
        );
      }
    }
  );
});

app.post("/cotizacion", (req, res) => {
  const { nombre, email, telefono, mensaje, catalogoId } = req.body;
  // Aquí puedes enviar los datos de la cotización a través de WhatsApp
});

// Ruta para la página de registro
app.get("/registro", (req, res) => {
  res.render("registro"); // Renderizar la vista de registro
});

// Ruta para el registro de usuarios
app.post("/registro", async (req, res) => {
  const {
    nombre,
    email,
    contraseña,
    rol,
    passwordAdmin, // Clave del administrador
    passwordSuperAdmin, // Nueva clave para el SuperAdmin
    montoVendedorInput,
    aceptarTerminos,
  } = req.body;

  if (rol === "admin") {
    const contraseñaAdminCorrecta = "z;Jpe[W*3Mqsc-TEAT6C"; // Contraseña del administrador correcta
    if (passwordAdmin !== contraseñaAdminCorrecta) {
      return res.status(400).send(
        // Contraseña de administrador incorrecta
        `<script>
        alert("Contraseña de administrador incorrecta");
        window.location.href = "/registro"; // Redirige al usuario de nuevo a la página de registro
      </script>
    `
      );
    }
  } else if (rol === "superadmin") {
    const contraseñaSuperAdminCorrecta = "BSdEGPAjxJwhv3onUX:a"; // Contraseña del SuperAdmin correcta
    if (passwordSuperAdmin !== contraseñaSuperAdminCorrecta) {
      return res.status(400).send(
        // Contraseña de SuperAdmin incorrecta
        `<script>
        alert("Contraseña de SuperAdmin incorrecta");
        window.location.href = "/registro"; // Redirige al usuario de nuevo a la página de registro
      </script>
    `
      );
    }
  } else if (rol === "vendedor") {
    const costoVendedor = "30000";
    if (!montoVendedorInput || montoVendedorInput < costoVendedor) {
      return res.status(400).send(
        //
        `<script>
          alert("El monto ingresado debe ser mayor a ${costoVendedor}");
          window.location.href = "/registro"; // Redirige al usuario de nuevo a la página de registro
        </script> ${costoVendedor}`
      );
    }
  } else if (!aceptarTerminos) {
    return res.status(400).send(`
      <script>
        alert("Debe aceptar los términos y condiciones para registrarse");
        window.location.href = "/registro"; // Redirige al usuario de nuevo a la página de registro
      </script>
    `);
  }
  try {
    // Hash de la contraseña
    const hashedPassword = await bcrypt.hash(contraseña, 10);

    // Verificar si el correo electrónico ya está en uso
    db.query(
      "SELECT * FROM usuarios WHERE email = ? OR nombre = ?",
      [email, nombre],
      (error, resultados) => {
        if (error) {
          res.status(500).send("Error interno del servidor");
        } else if (resultados.length > 0) {
          res.status(400).send(`
  <script>
    alert("El correo electrónico o el nombre de usuario ya están en uso");
    window.location.href = "/registro"; // Redirige al usuario de nuevo a la página de registro
  </script>
  `);
        } else {
          // Guardar el nuevo usuario en la base de datos con la contraseña hasheada
          db.query(
            "INSERT INTO usuarios (nombre, email, contraseña, rol) VALUES (?, ?, ?, ?)",
            [nombre, email, hashedPassword, rol],
            (error, resultado) => {
              if (error) {
                return res
                  .status(500)
                  .send("Error interno del servidor al guardar datos");
              }
              res.redirect("/inicio-sesion");
            }
          );
        }
      }
    );
  } catch (error) {
    console.error("Error al hashear la contraseña:", error);
    res.status(500).send("Error interno del servidor al hashear la contraseña");
  }
});

app.get("/catalogo", (req, res) => {
  // Verificar si el usuario ha iniciado sesión
  if (req.session.usuario) {
    // Obtener los vehículos de alguna fuente, por ejemplo, desde la base de datos
    const restaurantes = obtenerrestaurantes(); // Aquí debes implementar tu lógica para obtener los vehículos

    // Obtener el usuario de la sesión
    const usuario = req.session.usuario;

    // Renderizar la vista catalogo.ejs y pasar los vehículos y el usuario
    res.render("catalogo", { restaurantes: restaurantes, usuario: usuario });
  } else {
    // Si el usuario no ha iniciado sesión, redirigir a la página de inicio de sesión
    res.redirect("/inicio-sesion");
  }
});

// Ruta para la página de inicio de sesión
app.get("/inicio-sesion", (req, res) => {
  // Verificar si el usuario ha iniciado sesión
  if (req.session.usuario) {
    // Si el usuario ha iniciado sesión, redirigir a catalogo.ejs
    res.redirect("/catalogo");
  } else {
    // Si el usuario no ha iniciado sesión, renderizar la página de inicio de sesión
    res.render("inicio-sesion");
  }
});

// Ruta para el inicio de sesión de usuarios
app.post("/inicio-sesion", (req, res) => {
  const { email, contraseña } = req.body;
  // Buscar al usuario en la base de datos por su correo electrónico
  db.query(
    "SELECT * FROM usuarios WHERE email = ?",
    [email],
    async (error, resultados) => {
      if (error) {
        res.status(500).send("Error interno del servidor");
      } else if (resultados.length === 0) {
        res.status(401).send(`
              <script>
                  alert("El correo electrónico o la contraseña son incorrectas, por favor vuelve a intentarlo");
                  window.location.href = "/inicio-sesion"; // Redirige al usuario de nuevo a la página de inicio de sesion
              </script>
              `);
      } else {
        // Verificar la contraseña utilizando bcrypt
        const contraseñaHash = resultados[0].contraseña;
        const contraseñaValida = await bcrypt.compare(
          contraseña,
          contraseñaHash
        );
        if (!contraseñaValida) {
          res.status(401).send(`
                  <script>
                      alert("El correo electrónico o la contraseña son incorrectas, por favor vuelve a intentarlo");
                      window.location.href = "/inicio-sesion"; // Redirige al usuario de nuevo a la página de inicio de sesion
                  </script>
                  `);
        } else {
          // Obtener el rol del usuario
          const rol = resultados[0].rol;
          // Iniciar sesión y guardar el nombre de usuario y el rol en la sesión
          req.session.usuario = { nombre: resultados[0].nombre, rol: rol };
          res.redirect("/catalogo"); // Redirige a la página principal o a donde desees
        }
      }
    }
  );
});

app.post("/inicio-sesion", (req, res) => {
  // Verificar las credenciales del usuario y obtener el nombre de usuario
  const nombreDeUsuario = obtenerNombreDeUsuarioAlAutenticar(
    req.body.email,
    req.body.contraseña
  ); // Esta función debería verificar las credenciales y devolver el nombre de usuario

  // Guardar el nombre de usuario en la sesión
  req.session.usuario = { nombre: nombreDeUsuario };

  // Redirigir al usuario a la página principal después de iniciar sesión
  res.redirect("/catalogo");
});

app.get("/registrar-cita", (req, res) => {
  res.render("registrar-cita");
});

// Ruta para manejar la solicitud POST desde el formulario
app.post("/registrar-cita", (req, res) => {
  const { nombre, celular, motivo, fecha, hora } = req.body;

  // Query para verificar si la hora está ocupada
  const checkQuery =
    "SELECT COUNT(*) AS count FROM citas WHERE fecha = ? AND hora = ?";
  db.query(checkQuery, [fecha, hora], (checkError, checkResults) => {
    if (checkError) {
      console.error("Error al verificar la hora:", checkError);
      res.status(500).send("Error interno del servidor.");
      return;
    }

    if (checkResults[0].count > 0) {
      // Si la hora está ocupada, mostrar un alert
      res.send(
        '<script>alert("Esta hora ya está ocupada."); window.location.href = "/registrar-cita";</script>'
      );
      return;
    }

    // Si la hora no está ocupada, proceder a insertar la cita en la base de datos
    const insertQuery =
      "INSERT INTO citas (nombre, celular, motivo, fecha, hora) VALUES (?, ?, ?, ?, ?)";
    db.query(
      insertQuery,
      [nombre, celular, motivo, fecha, hora],
      (insertError, insertResults) => {
        if (insertError) {
          console.error("Error al registrar la cita:", insertError);
          res.status(500).send("Error interno del servidor.");
          return;
        }

        // Si la inserción es exitosa, mostrar un alert y redirigir al usuario al índice
        res.send(
          '<script>alert("Cita registrada exitosamente."); window.location.href = "/";</script>'
        );
      }
    );
  });
});

app.post("/agregar-catalogo", (req, res) => {
  const { marca, nombre, descripcion, certificacion, precio, imagen } =
    req.body;
  const nombreDeUsuario = req.session.usuario.nombre; // Obtener el nombre de usuario de la sesión

  // Realizar la inserción en la base de datos con el nombre de usuario
  db.query(
    "INSERT INTO restaurantes (marca, nombre, descripcion, certificacion, precio, imagen, UsuarioAgrego) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [
      marca,
      nombre,
      descripcion,
      certificacion,
      precio,
      imagen,
      nombreDeUsuario,
    ],
    (err, result) => {
      if (err) {
        console.error("Error al agregar vehículo:", err);
        res.status(500).send("Error interno del servidor");
      } else {
        res.redirect("/catalogo");
      }
    }
  );
});

// Ruta para cerrar sesión
app.get("/cerrar-sesion", (req, res) => {
  // Destruir la sesión del usuario
  req.session.destroy((err) => {
    if (err) {
      console.error("Error al cerrar sesión:", err);
      res.status(500).send("Error interno del servidor al cerrar sesión");
    } else {
      // Redirigir al usuario a la página de inicio de sesión u otra página
      res.redirect("/");
    }
  });
});

app.get("/inicio-sesion", (req, res) => {
  // Verificar si hay una sesión activa
  if (req.session.usuario) {
    // El usuario ha iniciado sesión
    // Puedes acceder al nombre de usuario usando req.session.usuario.nombre
    res.render("catalogo", { usuario: req.session.usuario.nombre });
  } else {
    // El usuario no ha iniciado sesión
    res.render("/", { usuario: null });
  }
});
// Middleware para verificar el rol del usuario
function verificarRol(rolPermitido) {
  return (req, res, next) => {
    if (
      req.session &&
      req.session.usuario &&
      req.session.usuario.rol === rolPermitido
    ) {
      next(); // El usuario tiene el rol adecuado, continuar con la siguiente ruta
    } else {
      res.status(403).send("Acceso denegado"); // El usuario no tiene permiso para acceder
    }
  };
}

// Ruta para agregar un vehículo
app.post("/agregar-catalogo", (req, res) => {
  // Lógica para agregar un vehículo a la base de datos
  const { marca, nombre, descripcion, certificacion, precio, imagen } =
    req.body;
  const usuarioAgrego = req.session.usuario.nombre; // Obtener el nombre del usuario que inició sesión
  // Agregar el vehículo a la base de datos
  res.redirect("/restaurantes"); // Redireccionar a la página de gestión de vehículos
});

app.get("/catalogo", (req, res) => {
  // Obtener el usuario de la sesión
  const usuario = req.session.usuario;

  // Obtener los vehículos del usuario actual
  const restaurantesDelUsuario = obtenerrestaurantes(usuario);

  // Renderizar la vista catalogo.ejs y pasar los vehículos y el usuario
  res.render("catalogo", { restaurantes: restaurantesDelUsuario, usuario: usuario });
});

app.get("/catalogo", (req, res) => {
  // Obtener datos de vehículos de la base de datos
  db.query("SELECT * FROM restaurantes", (err, results) => {
    if (err) {
      res.status(500).send("Error interno del servidor");
    } else {
      // Renderizar la vista de vehículos y pasar los datos de los vehículos y el usuario
      res.render("catalogo", { restaurantes: results, usuarios: req.user });
    }
  });
});





//Ruta para editar y eliminar restaurantes

// Ruta para editar un vehículo
app.get("/editar-catalogo/:id", (req, res) => {
  const catalogoId = req.params.id;
  // Obtener información del vehículo con el ID proporcionado
  db.query(
    "SELECT * FROM restaurantes WHERE id = ?",
    [catalogoId],
    (err, result) => {
      if (err) {
        console.error("Error al obtener información del vehículo:", err);
        res.status(500).send("Error interno del servidor");
      } else {
        // Renderizar el formulario de edición de vehículo y pasar los datos del vehículo
        res.render("editar-catalogo", {
          catalogo: result[0],
          usuario: req.session.usuario,
        });
      }
    }
  );
});

// Ruta para procesar la edición de un vehículo
app.post("/editar-catalogo/:id", (req, res) => {
  const catalogoId = req.params.id;
  const { marca, nombre, descripcion, certificacion, precio, imagen } =
    req.body;
  // Actualizar la información del vehículo en la base de datos
  db.query(
    "UPDATE restaurantes SET marca = ?, nombre = ?, descripcion = ?, certificacion = ?, precio = ?, imagen = ? WHERE id = ?",
    [marca, nombre, descripcion, certificacion, precio, imagen, catalogoId],
    (err, result) => {
      if (err) {
        console.error("Error al editar vehículo:", err);
        res.status(500).send("Error interno del servidor");
      } else {
        res.redirect("/catalogo"); // Redirigir a la página de vehículos después de editar
      }
    }
  );
});

// Ruta para borrar un vehículo
app.post("/borrar-catalogo/:id", (req, res) => {
  const catalogoId = req.params.id;

  // Mostrar un mensaje de confirmación al usuario antes de eliminar el vehículo
  res.send(
    `<script>
      if (confirm('¿Estás seguro de que deseas eliminar este producto?')) {
        fetch('/borrar-catalogo-confirmado/${catalogoId}', {
          method: 'DELETE'
        })
        .then(response => {
          if (response.ok) {
            alert('Producto eliminado correctamente');
            window.location.href = '/catalogo'; // Redirigir a la página de vehículos después de borrar
          } else {
            throw new Error('Error al intentar eliminar el vehículo');
          }
        })
        .catch(error => {
          console.error('Error al intentar eliminar el item:', error);
          alert('Hubo un error al intentar eliminar el item');
          window.location.href = '/catalogo'; // Redirigir a la página de vehículos en caso de error
        });
      } else {
        window.location.href = '/catalogo'; // Redirigir a la página de vehículos si el usuario cancela
      }
    </script>`
  );
});

// Ruta para confirmar la eliminación del vehículo
app.delete("/borrar-catalogo-confirmado/:id", (req, res) => {
  const catalogoId = req.params.id;
  // Eliminar el vehículo de la base de datos
  db.query(
    "DELETE FROM restaurantes WHERE id = ?",
    [catalogoId],
    (err, result) => {
      if (err) {
        console.error("Error al borrar vehículo:", err);
        res.status(500).send("Error interno del servidor");
      } else {
        res.sendStatus(200); // Enviar una respuesta exitosa al cliente
      }
    }
  );
});

// RUTAS PARA LOS restaurantes NUEVOS

//Ruta para 'gorras' en Express
app.get("/gorras", (req, res) => {
  // Obtener los vehículos de Toyota con la certificación "nuevo"
  obtenerrestaurantesPorMarcaYCertificacion(
    "Gorras",
    "siHay",
    (err, restaurantes) => {
      if (err) {
        // Manejar el error si ocurre
        console.error("Error al obtener el catalogo:", err);
        res.status(500).send("Error interno del servidor");
      } else {
        // Renderizar la vista 'gorras' y pasar los vehículos como datos
        res.render("restaurantes/gorras", { restaurantes });
      }
    }
  );
});

//Ruta para 'toyota-usado' en Express
app.get("/toyota-usado", (req, res) => {
  // Obtener los vehículos de Toyota con la certificación "usado"
  obtenerrestaurantesPorMarcaYCertificacion(
    "Toyota",
    "usado",
    (err, restaurantes) => {
      if (err) {
        // Manejar el error si ocurre
        console.error("Error al obtener vehículos:", err);
        res.status(500).send("Error interno del servidor");
      } else {
        // Renderizar la vista 'toyota-usado' y pasar los vehículos como datos
        res.render("restaurantes/toyota-usado", { restaurantes });
      }
    }
  );
});

//Ruta para 'vagon' en Express
app.get("/vagon", (req, res) => {
  // Obtener los vehículos de Toyota con la certificación "nuevo"
  obtenerrestaurantesPorMarcaYCertificacion("el vagon", "siHay", (err, restaurantes) => {
    if (err) {
      // Manejar el error si ocurre
      console.error("Error al obtener vagon:", err);
      res.status(500).send("Error interno del servidor");
    } else {
      // Renderizar la vista 'gorras' y pasar los vehículos como datos
      res.render("restaurantes/vagon", { restaurantes });
    }
  });
});

//Ruta para 'bmw-usado' en Express
app.get("/bmw-usado", (req, res) => {
  // Obtener los vehículos de Toyota con la certificación "nuevo"
  obtenerrestaurantesPorMarcaYCertificacion("BMW", "usado", (err, restaurantes) => {
    if (err) {
      // Manejar el error si ocurre
      console.error("Error al obtener vehículos:", err);
      res.status(500).send("Error interno del servidor");
    } else {
      // Renderizar la vista 'gorras' y pasar los vehículos como datos
      res.render("restaurantes/bmw-usado", { restaurantes });
    }
  });
});

//Ruta para 'chevrolet-nuevo' en Express
app.get("/chevrolet-nuevo", (req, res) => {
  // Obtener los vehículos de Toyota con la certificación "nuevo"
  obtenerrestaurantesPorMarcaYCertificacion(
    "Chevrolet",
    "nuevo",
    (err, restaurantes) => {
      if (err) {
        // Manejar el error si ocurre
        console.error("Error al obtener vehículos:", err);
        res.status(500).send("Error interno del servidor");
      } else {
        // Renderizar la vista 'gorras' y pasar los vehículos como datos
        res.render("restaurantes/chevrolet-nuevo", { restaurantes });
      }
    }
  );
});

//Ruta para 'chevrolet-usado' en Express
app.get("/chevrolet-usado", (req, res) => {
  // Obtener los vehículos de Toyota con la certificación "nuevo"
  obtenerrestaurantesPorMarcaYCertificacion(
    "Chevrolet",
    "usado",
    (err, restaurantes) => {
      if (err) {
        // Manejar el error si ocurre
        console.error("Error al obtener vehículos:", err);
        res.status(500).send("Error interno del servidor");
      } else {
        // Renderizar la vista 'gorras' y pasar los vehículos como datos
        res.render("restaurantes/chevrolet-usado", { restaurantes });
      }
    }
  );
});

//Ruta para 'mascotas' en Express
app.get("/mascotas", (req, res) => {
  // Obtener los vehículos de Toyota con la certificación "nuevo"
  obtenerrestaurantesPorMarcaYCertificacion(
    "Mascotas",
    "siHay",
    (err, restaurantes) => {
      if (err) {
        // Manejar el error si ocurre
        console.error("Error al obtener mascota:", err);
        res.status(500).send("Error interno del servidor");
      } else {
        // Renderizar la vista 'gorras' y pasar los vehículos como datos
        res.render("restaurantes/mascotas", { restaurantes });
      }
    }
  );
});

//Ruta para 'mercedez-benz-usado' en Express
app.get("/mercedez-benz-usado", (req, res) => {
  // Obtener los vehículos de Toyota con la certificación "nuevo"
  obtenerrestaurantesPorMarcaYCertificacion(
    "Mercedez-Benz",
    "usado",
    (err, restaurantes) => {
      if (err) {
        // Manejar el error si ocurre
        console.error("Error al obtener vehículos:", err);
        res.status(500).send("Error interno del servidor");
      } else {
        // Renderizar la vista 'gorras' y pasar los vehículos como datos
        res.render("restaurantes/mercedez-benz-usado", { restaurantes });
      }
    }
  );
});

//Ruta para 'nissan-nuevo' en Express
app.get("/nissan-nuevo", (req, res) => {
  // Obtener los vehículos de Toyota con la certificación "nuevo"
  obtenerrestaurantesPorMarcaYCertificacion(
    "Nissan",
    "nuevo",
    (err, restaurantes) => {
      if (err) {
        // Manejar el error si ocurre
        console.error("Error al obtener vehículos:", err);
        res.status(500).send("Error interno del servidor");
      } else {
        // Renderizar la vista 'gorras' y pasar los vehículos como datos
        res.render("restaurantes/nissan-nuevo", { restaurantes });
      }
    }
  );
});

//Ruta para 'nissan-usado' en Express
app.get("/nissan-usado", (req, res) => {
  // Obtener los vehículos de Toyota con la certificación "nuevo"
  obtenerrestaurantesPorMarcaYCertificacion(
    "Nissan",
    "usado",
    (err, restaurantes) => {
      if (err) {
        // Manejar el error si ocurre
        console.error("Error al obtener vehículos:", err);
        res.status(500).send("Error interno del servidor");
      } else {
        // Renderizar la vista 'gorras' y pasar los vehículos como datos
        res.render("restaurantes/nissan-usado", { restaurantes });
      }
    }
  );
});

//Ruta para 'renault-nuevo' en Express
app.get("/renault-nuevo", (req, res) => {
  // Obtener los vehículos de Toyota con la certificación "nuevo"
  obtenerrestaurantesPorMarcaYCertificacion(
    "Renault",
    "nuevo",
    (err, restaurantes) => {
      if (err) {
        // Manejar el error si ocurre
        console.error("Error al obtener vehículos:", err);
        res.status(500).send("Error interno del servidor");
      } else {
        // Renderizar la vista 'gorras' y pasar los vehículos como datos
        res.render("restaurantes/renault-nuevo", { restaurantes });
      }
    }
  );
});

//Ruta para 'renault-usado' en Express
app.get("/renault-usado", (req, res) => {
  // Obtener los vehículos de Toyota con la certificación "nuevo"
  obtenerrestaurantesPorMarcaYCertificacion(
    "Renault",
    "usado",
    (err, restaurantes) => {
      if (err) {
        // Manejar el error si ocurre
        console.error("Error al obtener vehículos:", err);
        res.status(500).send("Error interno del servidor");
      } else {
        // Renderizar la vista 'gorras' y pasar los vehículos como datos
        res.render("restaurantes/renault-usado", { restaurantes });
      }
    }
  );
});

// Escuchar en el puerto
app.listen(port, () => {
  console.log(`Servidor iniciado en http://localhost:${port}`);
});

function obtenerrestaurantesPorMarcaYCertificacion(
  marca,
  certificacion,
  callback
) {
  // Consulta SQL para obtener los vehículos según la marca y la certificación
  const sql = `SELECT * FROM restaurantes WHERE marca = ? AND certificacion = ?`;

  // Ejecutar la consulta SQL
  db.query(sql, [marca, certificacion], (err, results) => {
    if (err) {
      console.error("Error al obtener vehículos:", err);
      return callback(err, null);
    }

    // Devolver los resultados de la consulta
    callback(null, results);
  });
}

function obtenerrestaurantes(usuario, callback) {
  // Consulta SQL para obtener los vehículos del usuario actual
  const sql = `SELECT * FROM restaurantes WHERE usuarioAgrego = ?`;

  // Ejecutar la consulta SQL
  db.query(sql, [usuario.nombre], (err, results) => {
    if (err) {
      console.error("Error al obtener vehículos:", err);
      return callback(err, null);
    }

    // Devolver los resultados de la consulta
    callback(null, results);
  });

  const restaurantesDelUsuario = restaurantes.filter(
    (catalogo) => catalogo.UsuarioAgrego === usuario.nombre
  );

  return restaurantesDelUsuario;
}

// Estructura del carrito de compras
let carrito = {};

// Middleware para agregar productos al carrito
app.post('/agregar-al-carrito', (req, res) => {
  const { productoId, cantidad } = req.body;

  // Verifica si el producto ya está en el carrito
  if (carrito[productoId]) {
      carrito[productoId] += parseInt(cantidad);
  } else {
      carrito[productoId] = parseInt(cantidad);
  }

  // Envía una respuesta indicando que el producto se agregó al carrito
  res.json({ mensaje: 'Producto agregado al carrito' });
});


