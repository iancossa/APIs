//mongodb file ready
require("./config/db");

const app = require("express")();
const port = 3000;

const UserRouter = require("./api/routes/User");

//for accepting post form data
const bodyParser = require("express").json;
app.use(bodyParser());

app.listen(port, () => {
  console.log("Server running brothers on port ${port}");
});
