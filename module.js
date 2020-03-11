//Relative Module
//Relative User
//Relative Login
//Relative Connection
UserManager = function () {var _c_this = this;


}

UserManager.Module = function () {var _c_this = this;
	this.userCreate = null;

	this.userGet = null;

	this.loginView = null;

	this.groupCounts = null;

	this.server = null;

	this.baseConfig = null;

	this.containers = [];

	this.bridges = [];

	this.registeredCollections = [];

	this.registeredPermissions = [];

	this.name = "";

	this.id = "";

	this.root = "";

	this.version = "";

	this.author = "";

	this.license = "";

	this.repo = "";

	this.users = null;

	this.logins = null;

	if (arguments.length == 1 && ((arguments[0] instanceof Websom.Server) || typeof arguments[0] == 'undefined' || arguments[0] === null)) {
		var server = arguments[0];
		_c_this.server = server;
		_c_this.registerWithServer();
	}

}

/*i async*/UserManager.Module.prototype.start = async function () {var _c_this = this; var _c_root_method_arguments = arguments;
	if (arguments.length == 0) {
		_c_this.server.confirmation.handleConfirmation("emailVerification", function (exec) {
			console.log(exec.key);
			});
	}
}

UserManager.Module.prototype.registerWithServer = function () {var _c_this = this; var _c_root_method_arguments = arguments;
	if (arguments.length == 0) {
		_c_this.server.userSystem = _c_this;
	}
}

UserManager.Module.prototype.permissions = function () {var _c_this = this; var _c_root_method_arguments = arguments;
	if (arguments.length == 0) {
		_c_this.userGet = new Websom.Permission("User.Get");
		_c_this.userGet.description = "Allows the public to read users (username, and time created) querying on their id.";
		_c_this.userGet.public = true;
		_c_this.userCreate = new Websom.Permission("User.Create");
		_c_this.userCreate.description = "Allows the public to create a user account.";
		_c_this.userCreate.public = true;
		_c_this.registerPermission(_c_this.userCreate);
		_c_this.registerPermission(_c_this.userGet);
		_c_this.loginView = new Websom.Permission("LoginAttempts.View");
		_c_this.loginView.description = "Administrator view";
		_c_this.registerPermission(_c_this.loginView);
	}
}

/*i async*/UserManager.Module.prototype.getUserFromRequest = async function () {var _c_this = this; var _c_root_method_arguments = arguments;
	if (arguments.length == 1 && ((arguments[0] instanceof Websom.Request) || typeof arguments[0] == 'undefined' || arguments[0] === null)) {
		var req = arguments[0];
/*async*/
		var userId = req.session.get("user");
		if (userId == null) {
			return null;
			}
		var user = (await _c_this.users.getEntity/* async call */(userId));
		return user;
	}
}

/*i async*/UserManager.Module.prototype.collections = async function () {var _c_this = this; var _c_root_method_arguments = arguments;
	if (arguments.length == 0) {
/*async*/
		var db = _c_this.server.database.central;
		_c_this.users = db.collection("users");
		_c_this.groupCounts = new Websom.Calculators.KeyCount("groups", "array");
		UserManager.User.applySchema(_c_this.users).calc("groupCounts", _c_this.groupCounts).index().field("name", "==").field("created", "dsc");
		(await _c_this.registerCollection/* async call */(_c_this.users));
		_c_this.logins = db.collection("logins");
		UserManager.Login.applySchema(_c_this.logins).index().field("user", "==").field("created", "dsc");
		(await _c_this.registerCollection/* async call */(_c_this.logins));
		_c_this.server.api.interface(_c_this.logins, "/logins").route("/search").auth(_c_this.loginView).executes("select").read("user").read("created").read("id").read("flagged").read("success").read("location").read("ip").filter("default").filter("user").field("user", "==");
		_c_this.server.api.interface(_c_this.users, "/users").route("/create").auth(_c_this.userCreate).executes("insert").write("username").format("single-line").regexTest("^([A-Za-z0-9_-]*)$").limit(3, 256).unique().write("password").regexTest("^[ -~]*$").limit(8, 256).mutate(function (collection, req, value) {
			return _c_this.server.crypto.hashPassword(value);
			}).write("email").format("email").unique().setComputed("created", function (req) {
			return Websom.Time.now();
			}).set("banned", false).set("verified", false).set("locked", false).set("connected", false).set("groups", []).route("/get").auth(_c_this.userGet).executes("select").read("username").read("created").filter("default");
		_c_this.server.api.route("/login").input("login").type("string").limit(3, 256).input("password").type("string").limit(8, 256).executes(async function (ctx) {
/*async*/
			var login = ctx.get("login");
			var password = ctx.get("password");
			var emailValidator = new Websom.Restrictions.Format("email");
			var userResults = null;
			if ((await emailValidator.testServer/* async call */(null, null, login))) {
/*async*/
				userResults = (await _c_this.users.where("email", "==", login).get/* async call */());
				}else{
/*async*/
					userResults = (await _c_this.users.where("username", "==", login).get/* async call */());
				}
			if (userResults.documents.length == 0) {
				ctx.request.endWithError("Invalid username or password");
				return null;
				}
			var user = (await _c_this.users.makeEntity/* async call */(userResults.documents[0]));
			var passedPassword = _c_this.server.crypto.verifyPassword(user.password, password);
			if (user.verified == false) {
				var mp = {};
				mp["id"] = user.id;
				ctx.request.endWithComponent("user-unverified-status", mp);
				return null;
				}
			if (passedPassword) {
/*async*/
				(await _c_this.logLogin/* async call */(ctx.request.client.address, "", user, true, false));
				ctx.request.session.set("user", user.id);
				ctx.request.endWithSuccess("Login successful");
				}else{
/*async*/
					(await _c_this.logLogin/* async call */(ctx.request.client.address, "", user, false, false));
					ctx.request.endWithError("Invalid username or password");
				}
			});
		_c_this.server.api.route("/resend-verification-email").input("id").type("string").limit(1, 255).executes(async function (ctx) {
/*async*/
			var user = (await _c_this.users.getEntity/* async call */(ctx.get("id")));
			if (user == null) {
				ctx.request.endWithError("Invalid id");
				return null;
				}
			if ((await _c_this.sendVerificationEmail/* async call */(user))) {
				ctx.request.endWithSuccess("Verification sent");
				}else{
					ctx.request.endWithError("Error while sending verification");
				}
			});
	}
}

/*i async*/UserManager.Module.prototype.sendVerificationEmail = async function () {var _c_this = this; var _c_root_method_arguments = arguments;
	if (arguments.length == 1 && ((arguments[0] instanceof UserManager.User) || typeof arguments[0] == 'undefined' || arguments[0] === null)) {
		var user = arguments[0];
/*async*/
		var mp = {};
		mp["id"] = user.id;
		console.log("Sending email to " + user.email);
		(await _c_this.server.confirmation.confirm("emailVerification").via("email").using("link").to(user.email).store(mp).subject("Email verification").message("Click here to finalize your account verification.").dispatch/* async call */());
		return true;
	}
}

/*i async*/UserManager.Module.prototype.logLogin = async function () {var _c_this = this; var _c_root_method_arguments = arguments;
	if (arguments.length == 5 && (typeof arguments[0] == 'string' || typeof arguments[0] == 'undefined' || arguments[0] === null) && (typeof arguments[1] == 'string' || typeof arguments[1] == 'undefined' || arguments[1] === null) && ((arguments[2] instanceof UserManager.User) || typeof arguments[2] == 'undefined' || arguments[2] === null) && (typeof arguments[3] == 'boolean' || typeof arguments[3] == 'undefined' || arguments[3] === null) && (typeof arguments[4] == 'boolean' || typeof arguments[4] == 'undefined' || arguments[4] === null)) {
		var ip = arguments[0];
		var location = arguments[1];
		var user = arguments[2];
		var success = arguments[3];
		var flagged = arguments[4];
/*async*/
		(await _c_this.logins.insert().set("created", Websom.Time.now()).set("ip", ip).set("location", location).set("user", user.id).set("success", success).set("flagged", flagged).run/* async call */());
	}
}

UserManager.Module.prototype.clientData = function () {var _c_this = this; var _c_root_method_arguments = arguments;
	if (arguments.length == 2 && ((arguments[0] instanceof Websom.Request) || typeof arguments[0] == 'undefined' || arguments[0] === null) && (typeof arguments[1] == 'function' || typeof arguments[1] == 'undefined' || arguments[1] === null)) {
		var req = arguments[0];
		var send = arguments[1];
		return false;
	}
}

UserManager.Module.prototype.spawn = function () {var _c_this = this; var _c_root_method_arguments = arguments;
	if (arguments.length == 1 && (typeof arguments[0] == 'object' || typeof arguments[0] == 'undefined' || arguments[0] === null)) {
		var config = arguments[0];
		_c_this.baseConfig = config;
		_c_this.name = config["name"];
		_c_this.id = config["id"];
	}
}

UserManager.Module.prototype.stop = function () {var _c_this = this; var _c_root_method_arguments = arguments;
	if (arguments.length == 0) {

	}
}

UserManager.Module.prototype.configure = function () {var _c_this = this; var _c_root_method_arguments = arguments;
	if (arguments.length == 0) {

	}
}

/*i async*/UserManager.Module.prototype.registerCollection = async function (collection) {var _c_this = this; var _c_root_method_arguments = arguments;
/*async*/
		_c_this.registeredCollections.push(collection);
		if (_c_this.server.config.dev) {
/*async*/
			if (collection.appliedSchema != null) {
/*async*/
				(await collection.appliedSchema.register/* async call */());
				}
			}}

UserManager.Module.prototype.registerPermission = function () {var _c_this = this; var _c_root_method_arguments = arguments;
	if (arguments.length == 1 && ((arguments[0] instanceof Websom.Permission) || typeof arguments[0] == 'undefined' || arguments[0] === null)) {
		var permission = arguments[0];
		_c_this.registeredPermissions.push(permission);
	}
else 	if (arguments.length == 1 && (typeof arguments[0] == 'string' || typeof arguments[0] == 'undefined' || arguments[0] === null)) {
		var permission = arguments[0];
		var perm = new Websom.Permission(permission);
		_c_this.registeredPermissions.push(perm);
		return perm;
	}
}

UserManager.Module.prototype.setupData = function () {var _c_this = this; var _c_root_method_arguments = arguments;
	if (arguments.length == 0) {

	}
}

UserManager.Module.prototype.setupBridge = function () {var _c_this = this; var _c_root_method_arguments = arguments;
	if (arguments.length == 0) {

	}
}

UserManager.Module.prototype.pullFromGlobalScope = function () {var _c_this = this; var _c_root_method_arguments = arguments;
	if (arguments.length == 1 && (typeof arguments[0] == 'string' || typeof arguments[0] == 'undefined' || arguments[0] === null)) {
		var name = arguments[0];
		
			return global[name];
		
	}
}

UserManager.Module.prototype.setupBridges = function () {var _c_this = this; var _c_root_method_arguments = arguments;
	if (arguments.length == 0) {
		var bridges = [];
		return bridges;
	}
}

//Relative Carbon
//Relative Context
//Relative Error
//Relative FileSystem
//Relative Buffer
//Relative File
//Relative Stat
//Relative primitive
//Relative object
//Relative array
//Relative bool
//Relative byte
//Relative char
//Relative Console
//Relative everything
//Relative Exception
//Relative float
//Relative function
//Relative int
//Relative uint
//Relative uint8
//Relative int8
//Relative uint16
//Relative int16
//Relative uint32
//Relative int32
//Relative uint64
//Relative int64
//Relative map
//Relative null
//Relative empty
//Relative void
//Relative string
//Relative Math
UserManager.Login = function () {var _c_this = this;
	this.collection = null;

	this.id = "";

	this.user = null;

	this.created = null;

	this.ip = "";

	this.location = "";

	this.success = false;

	this.flagged = false;

	if (arguments.length == 0) {

	}

}

/*i async*/UserManager.Login.prototype.load = async function () {var _c_this = this; var _c_root_method_arguments = arguments;
	if (arguments.length == 0) {
/*async*/
		var doc = (await _c_this.collection.document/* async call */(_c_this.id));
		(await _c_this.loadFromMap/* async call */(doc.data()));
	}
}

/*i async*/UserManager.Login.prototype.loadEntityArray = async function () {var _c_this = this; var _c_root_method_arguments = arguments;
	if (arguments.length == 1 && (arguments[0] instanceof Array || typeof arguments[0] == 'undefined' || arguments[0] === null)) {
		var arr = arguments[0];
/*async*/
		if (arr.length > 0) {
/*async*/
			var collection = arr[0].collection;
			var ids = [];
			for (var i = 0; i < arr.length; i++) {
				ids.push(arr[i].id);
				}
			var docs = (await collection.getAll/* async call */(ids));
			for (var i = 0; i < docs.length; i++) {
/*async*/
				var doc = docs[i];
				var entity = arr.find(function (ent) {
					return ent.id == doc.id;
					});
				(await entity.loadFromMap/* async call */(doc.data()));
				}
			}
	}
}

UserManager.Login.applySchema = function (collection) {var _c_this = this; var _c_root_method_arguments = arguments;
		_c_this.linkToCollection(collection);
		
			return this.getSchema(collection);
		
		}

UserManager.Login.linkToCollection = function (collection) {var _c_this = this; var _c_root_method_arguments = arguments;
		
			collection.entityTemplate = this;
		
		}

/*i async*/UserManager.Login.prototype.loadFromMap = async function () {var _c_this = this; var _c_root_method_arguments = arguments;
	if (arguments.length == 1 && (typeof arguments[0] == 'object' || typeof arguments[0] == 'undefined' || arguments[0] === null)) {
		var data = arguments[0];
		
			for (let k in data) {
				if (data.hasOwnProperty(k) && this.hasOwnProperty(k)) {
					let camel = k[0].toUpperCase() + k.substr(1, k.length);

					if (this["load" + camel]) {
						await this["load" + camel](data[k]);
					}else{
						this[k] = data[k];
					}
				}
			}
		
		
	}
}

UserManager.Login.getSchema = function (collection) {var _c_this = this; var _c_root_method_arguments = arguments;
		return collection.schema().field("user", "string").field("created", "string").field("ip", "string").field("location", "string").field("success", "string").field("flagged", "string");}

UserManager.User = function () {var _c_this = this;
	this.collection = null;

	this.id = "";

	this.username = "";

	this.email = "";

	this.password = "";

	this.firstName = "";

	this.lastName = "";

	this.department = "";

	this.company = "";

	this.address = "";

	this.city = "";

	this.state = "";

	this.country = "";

	this.postCode = "";

	this.role = "";

	this.created = null;

	this.lastLogin = null;

	this.lastBan = null;

	this.banned = false;

	this.verified = false;

	this.connected = false;

	this.locked = false;

	this.groups = [];

	this.loginAttempts = null;

	this.connections = null;

	this.collection = null;

	this.id = "";

	if (arguments.length == 0) {

	}
else 	if (arguments.length == 0) {

	}

}

/*i async*/UserManager.User.prototype.load = async function () {var _c_this = this; var _c_root_method_arguments = arguments;
	if (arguments.length == 0) {
/*async*/
		var doc = (await _c_this.collection.document/* async call */(_c_this.id));
		(await _c_this.loadFromMap/* async call */(doc.data()));
	}
}

/*i async*/UserManager.User.prototype.loadEntityArray = async function () {var _c_this = this; var _c_root_method_arguments = arguments;
	if (arguments.length == 1 && (arguments[0] instanceof Array || typeof arguments[0] == 'undefined' || arguments[0] === null)) {
		var arr = arguments[0];
/*async*/
		if (arr.length > 0) {
/*async*/
			var collection = arr[0].collection;
			var ids = [];
			for (var i = 0; i < arr.length; i++) {
				ids.push(arr[i].id);
				}
			var docs = (await collection.getAll/* async call */(ids));
			for (var i = 0; i < docs.length; i++) {
/*async*/
				var doc = docs[i];
				var entity = arr.find(function (ent) {
					return ent.id == doc.id;
					});
				(await entity.loadFromMap/* async call */(doc.data()));
				}
			}
	}
}

UserManager.User.applySchema = function (collection) {var _c_this = this; var _c_root_method_arguments = arguments;
		_c_this.linkToCollection(collection);
		
			return this.getSchema(collection);
		
		}

UserManager.User.linkToCollection = function (collection) {var _c_this = this; var _c_root_method_arguments = arguments;
		
			collection.entityTemplate = this;
		
		}

/*i async*/UserManager.User.prototype.loadFromMap = async function () {var _c_this = this; var _c_root_method_arguments = arguments;
	if (arguments.length == 1 && (typeof arguments[0] == 'object' || typeof arguments[0] == 'undefined' || arguments[0] === null)) {
		var data = arguments[0];
		
			for (let k in data) {
				if (data.hasOwnProperty(k) && this.hasOwnProperty(k)) {
					let camel = k[0].toUpperCase() + k.substr(1, k.length);

					if (this["load" + camel]) {
						await this["load" + camel](data[k]);
					}else{
						this[k] = data[k];
					}
				}
			}
		
		
	}
}

UserManager.User.getSchema = function (collection) {var _c_this = this; var _c_root_method_arguments = arguments;
		return collection.schema().field("username", "string").field("email", "string").field("password", "string").field("firstName", "string").field("lastName", "string").field("department", "string").field("company", "string").field("address", "string").field("city", "string").field("state", "string").field("country", "string").field("postCode", "string").field("role", "string").field("created", "string").field("lastLogin", "string").field("lastBan", "string").field("banned", "string").field("verified", "string").field("connected", "string").field("locked", "string").field("groups", "string");}


module.exports = UserManager.Module;