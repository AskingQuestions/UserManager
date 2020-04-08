//Relative Module
//Relative User
//Relative Login
//Relative Connection
UserManager = function () {var _c_this = this;


}

UserManager.Module = function (server) {var _c_this = this;
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

		_c_this.server = server;
		_c_this.registerWithServer();
}

/*i async*/UserManager.Module.prototype.start = async function () {var _c_this = this; var _c_root_method_arguments = arguments;
		_c_this.server.confirmation.handleConfirmation("emailVerification", async function (exec) {
/*async*/
			var id = exec.storage["id"];
			var user = (await _c_this.users.getEntity/* async call */(id));
			user.verified = true;
			(await user.saveToCollection/* async call */());
			});
		_c_this.server.confirmation.handleConfirmation("passwordReset", async function (exec) {
/*async*/
			var id = exec.storage["id"];
			var user = (await _c_this.users.getEntity/* async call */(id));
			if (exec.params == null || (typeof exec.params == 'object' ? (Array.isArray(exec.params) ? 'array' : 'map') : (typeof exec.params == 'number' ? 'float' : typeof exec.params)) != "map") {
/*async*/
				(await exec.request.endWithError/* async call */("Invalid params"));
				return null;
				}
			var newPassword = exec.params["password"];
			if ((typeof newPassword == 'object' ? (Array.isArray(newPassword) ? 'array' : 'map') : (typeof newPassword == 'number' ? 'float' : typeof newPassword)) == "string" && newPassword.length > 3 && newPassword.length < 256) {
/*async*/
				user.password = (await _c_this.server.crypto.hashPassword/* async call */(newPassword));
				(await user.saveToCollection/* async call */());
				}else{
/*async*/
					(await exec.request.endWithError/* async call */("Invalid password"));
				}
			});}

UserManager.Module.prototype.registerWithServer = function () {var _c_this = this; var _c_root_method_arguments = arguments;
		_c_this.server.userSystem = _c_this;}

UserManager.Module.prototype.permissions = function () {var _c_this = this; var _c_root_method_arguments = arguments;
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
		_c_this.registerPermission(_c_this.loginView);}

/*i async*/UserManager.Module.prototype.getUserFromRequest = async function (req) {var _c_this = this; var _c_root_method_arguments = arguments;
/*async*/
		var userId = (await req.session.get/* async call */("user"));
		if (userId == null) {
			return null;
			}
		var user = (await _c_this.users.getEntity/* async call */(userId));
		return user;}

/*i async*/UserManager.Module.prototype.collections = async function () {var _c_this = this; var _c_root_method_arguments = arguments;
/*async*/
		var verified = _c_this.server.getConfigPrimitive("module.userSystem", "requireVerification");
		verified = verified == false;
		var db = _c_this.server.database.central;
		_c_this.users = db.collection("users");
		_c_this.groupCounts = new Websom.Calculators.KeyCount("groups", "array");
		UserManager.User.applySchema(_c_this.users).calc("groupCounts", _c_this.groupCounts).index().field("name", "==").field("created", "dsc");
		(await _c_this.registerCollection/* async call */(_c_this.users));
		_c_this.logins = db.collection("logins");
		UserManager.Login.applySchema(_c_this.logins).index().field("user", "==").field("created", "dsc");
		(await _c_this.registerCollection/* async call */(_c_this.logins));
		_c_this.server.api.interface(_c_this.logins, "/logins").route("/search").auth(_c_this.loginView).executes("select").read("id").read("user").read("created").read("id").read("flagged").read("success").read("location").read("ip").filter("default").filter("user").field("user", "==");
		_c_this.server.api.interface(_c_this.users, "/users").route("/create").auth(_c_this.userCreate).executes("insert").write("username").format("single-line").regexTest("^([A-Za-z0-9_-]*)$").limit(3, 256).unique().write("password").regexTest("^[ -~]*$").limit(8, 256).mutate(async function (collection, req, value) {
/*async*/
			return (await _c_this.server.crypto.hashPassword/* async call */(value));
			}).write("email").format("email").unique().setComputed("created", function (req) {
			return Websom.Time.now();
			}).set("banned", false).set("verified", verified).set("locked", false).set("connected", false).set("connectedAdapter", "").set("groups", []).route("/get").auth(_c_this.userGet).executes("select").read("username").read("created").read("id").read("bio").read("social").read("nickname").filter("default").field("id", "==").route("user-info").auth(_c_this.userGet).executes("select").read("id").read("username").read("created").read("email").read("firstName").read("lastName").filter("default", async function (req, query) {
/*async*/
			var userId = (await req.session.get/* async call */("user"));
			if (userId == null) {
/*async*/
				(await req.endWithError/* async call */("Not logged in"));
				return null;
				}
			query.where("id", "==", userId);
			});
		_c_this.server.api.route("/users/connection-sign-in").auth(_c_this.userCreate).input("adapter").type("string").input("data").type("map").executes(async function (ctx) {
/*async*/
			var adapter = ctx.get("adapter");
			var data = ctx.get("data");
			(await _c_this.handleConnectionSignin/* async call */(ctx.request, adapter, data));
			});
		_c_this.server.api.route("/logout").executes(async function (ctx) {
/*async*/
			(await ctx.request.session.delete/* async call */("user"));
			(await ctx.request.endWithSuccess/* async call */("Signed out"));
			});
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
/*async*/
				(await ctx.request.endWithError/* async call */("Invalid username or password"));
				return null;
				}
			var user = (await _c_this.users.makeEntity/* async call */(userResults.documents[0]));
			var passedPassword = (await _c_this.server.crypto.verifyPassword/* async call */(user.password, password));
			if (user.verified == false) {
/*async*/
				var mp = {};
				mp["id"] = user.id;
				(await ctx.request.endWithComponent/* async call */("user-unverified-status", mp));
				return null;
				}
			if (user.connected) {
/*async*/
				(await ctx.request.endWithError/* async call */("Please login using " + user.connectedAdapter));
				return null;
				}
			if (passedPassword) {
/*async*/
				(await _c_this.logLogin/* async call */(ctx.request.client.address, "", user, true, false));
				(await ctx.request.session.set/* async call */("user", user.id));
				(await ctx.request.endWithSuccess/* async call */("Login successful"));
				}else{
/*async*/
					(await _c_this.logLogin/* async call */(ctx.request.client.address, "", user, false, false));
					(await ctx.request.endWithError/* async call */("Invalid username or password"));
				}
			});
		_c_this.server.api.route("/resend-verification-email").input("id").type("string").limit(1, 255).executes(async function (ctx) {
/*async*/
			var user = (await _c_this.users.getEntity/* async call */(ctx.get("id")));
			if (user == null) {
/*async*/
				(await ctx.request.endWithError/* async call */("Invalid id"));
				return null;
				}
			if ((await _c_this.sendVerificationEmail/* async call */(user))) {
/*async*/
				(await ctx.request.endWithSuccess/* async call */("Verification sent"));
				}else{
/*async*/
					(await ctx.request.endWithError/* async call */("Error while sending verification"));
				}
			});
		_c_this.server.api.route("/reset-password").input("email").type("string").format("email").limit(1, 255).executes(async function (ctx) {
/*async*/
			var email = ctx.get("email");
			var docs = (await _c_this.users.where("email", "==", email).get/* async call */());
			if (docs.documents.length > 0) {
/*async*/
				var doc = (await _c_this.users.makeEntity/* async call */(docs.documents[0]));
				if ((await _c_this.sendPasswordReset/* async call */(doc)) == false) {
/*async*/
					(await ctx.request.endWithError/* async call */("Error while sending password reset."));
					}
				}
			(await ctx.request.endWithSuccess/* async call */("Password reset sent! Please check your inbox."));
			});}

/*i async*/UserManager.Module.prototype.sendVerificationEmail = async function (user) {var _c_this = this; var _c_root_method_arguments = arguments;
/*async*/
		var mp = {};
		mp["id"] = user.id;
		console.log("Sending email to " + user.email);
		(await _c_this.server.confirmation.confirm("emailVerification").via("email").using("link").to(user.email).store(mp).subject("Email verification").message("Click here to finalize your account verification.").dispatch/* async call */());
		return true;}

/*i async*/UserManager.Module.prototype.sendPasswordReset = async function (user) {var _c_this = this; var _c_root_method_arguments = arguments;
/*async*/
		var mp = {};
		mp["id"] = user.id;
		(await _c_this.server.confirmation.confirm("passwordReset").via("email").using("link").to(user.email).store(mp).subject("Password Reset").message("Click here to reset your password.").dispatch/* async call */());
		return true;}

/*i async*/UserManager.Module.prototype.logLogin = async function (ip, location, user, success, flagged) {var _c_this = this; var _c_root_method_arguments = arguments;
/*async*/
		(await _c_this.logins.insert().set("created", Websom.Time.now()).set("ip", ip).set("location", location).set("user", user.id).set("success", success).set("flagged", flagged).run/* async call */());}

/*i async*/UserManager.Module.prototype.loginWithConnection = async function (req, adapter, user) {var _c_this = this; var _c_root_method_arguments = arguments;
/*async*/
		(await _c_this.logLogin/* async call */(req.client.address, "", user, true, false));
		(await req.session.set/* async call */("user", user.id));
		(await req.endWithSuccess/* async call */("Login successful"));}

/*i async*/UserManager.Module.prototype.createUserWithConnection = async function (req, adapter, user) {var _c_this = this; var _c_root_method_arguments = arguments;
/*async*/
		var res = (await _c_this.users.insert().set("username", user.username).set("firstName", user.firstName).set("lastName", user.lastName).set("password", "").set("email", user.email).set("created", Websom.Time.now()).set("banned", false).set("verified", true).set("locked", false).set("connected", true).set("connectedAdapter", adapter).set("groups", []).run/* async call */());
		var userEntity = new UserManager.User();
		userEntity.id = res.id;
		userEntity.collection = _c_this.users;
		(await _c_this.loginWithConnection/* async call */(req, adapter, userEntity));}

/*i async*/UserManager.Module.prototype.handleConnectionSignin = async function (req, adapter, data) {var _c_this = this; var _c_root_method_arguments = arguments;
/*async*/
		var adapterInterface = _c_this.server.adapt("connection");
		if ((await adapterInterface.loadAsBranchAdapter/* async call */(adapter))) {
/*async*/
			var cAdapter = adapterInterface.adapter;
			var user = (await cAdapter.getUser/* async call */(data));
			if (user == null) {
/*async*/
				(await req.endWithError/* async call */("Authentication error"));
				return null;
				}
			var userRes = (await _c_this.users.where("email", "==", user.email).get/* async call */());
			if (userRes.documents.length == 0) {
/*async*/
				(await _c_this.createUserWithConnection/* async call */(req, adapter, user));
				}else{
/*async*/
					var userEntity = (await _c_this.users.makeEntity/* async call */(userRes.documents[0]));
					if (userEntity.connected) {
/*async*/
						if (userEntity.connectedAdapter == adapter) {
/*async*/
							(await _c_this.loginWithConnection/* async call */(req, adapter, userEntity));
							}else{
/*async*/
								(await req.endWithError/* async call */("Please sign in through " + adapter));
								return null;
							}
						}else{
/*async*/
							(await req.endWithError/* async call */("Please sign in using your email and password"));
							return null;
						}
				}
			}else{
/*async*/
				(await req.endWithError/* async call */("Unknown adapter " + adapter));
			}}

UserManager.Module.prototype.clientData = function (req, send) {var _c_this = this; var _c_root_method_arguments = arguments;
		return false;}

UserManager.Module.prototype.spawn = function (config) {var _c_this = this; var _c_root_method_arguments = arguments;
		_c_this.baseConfig = config;
		_c_this.name = config["name"];
		_c_this.id = config["id"];}

UserManager.Module.prototype.stop = function () {var _c_this = this; var _c_root_method_arguments = arguments;
}

UserManager.Module.prototype.configure = function () {var _c_this = this; var _c_root_method_arguments = arguments;
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
}

UserManager.Module.prototype.setupBridge = function () {var _c_this = this; var _c_root_method_arguments = arguments;
}

UserManager.Module.prototype.pullFromGlobalScope = function (name) {var _c_this = this; var _c_root_method_arguments = arguments;
		
			return global[name];
		}

UserManager.Module.prototype.setupBridges = function () {var _c_this = this; var _c_root_method_arguments = arguments;
		var bridges = [];
		return bridges;}

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
	this.rawFields = null;

	this.collection = null;

	this.id = "";

	this.user = null;

	this.created = null;

	this.ip = "";

	this.location = "";

	this.success = false;

	this.flagged = false;


}

/*i async*/UserManager.Login.prototype.load = async function () {var _c_this = this; var _c_root_method_arguments = arguments;
/*async*/
		var doc = (await _c_this.collection.document/* async call */(_c_this.id));
		(await _c_this.loadFromMap/* async call */(doc.data()));}

/*i async*/UserManager.Login.prototype.loadEntityArray = async function (arr) {var _c_this = this; var _c_root_method_arguments = arguments;
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
			}}

UserManager.Login.applySchema = function (collection) {var _c_this = this; var _c_root_method_arguments = arguments;
		_c_this.linkToCollection(collection);
		
			return this.getSchema(collection);
		
		}

UserManager.Login.linkToCollection = function (collection) {var _c_this = this; var _c_root_method_arguments = arguments;
		
			collection.entityTemplate = this;
		
		}

UserManager.Login.prototype.getFieldValue = function (field) {var _c_this = this; var _c_root_method_arguments = arguments;
		
			return this[field];
		
		}

UserManager.Login.prototype.getFieldsChanged = function () {var _c_this = this; var _c_root_method_arguments = arguments;
		var fieldsChanged = [];
		for (var i = 0; i < _c_this.collection.appliedSchema.fields.length; i++) {
			var field = _c_this.collection.appliedSchema.fields[i];
			var realValue = null;
			var myValue = _c_this.getFieldValue(field.name);
			var rawValue = _c_this.rawFields[field.name];
			var isDifferent = false;
			if (field.type == "time") {
				var cast = myValue;
				if (cast == null) {
					realValue = null;
					}else{
						realValue = cast.timestamp;
					}
				isDifferent = realValue != rawValue;
				}else if (field.type == "reference") {
				var cast = myValue;
				if (cast != null) {
					realValue = cast.id;
					}
				isDifferent = realValue != rawValue;
				}else if (field.type == "array") {
				
					isDifferent = JSON.stringify(myValue) != JSON.stringify(rawValue);
				
				
				}else{
					realValue = myValue;
					isDifferent = realValue != rawValue;
				}
			if (isDifferent) {
				fieldsChanged.push(field);
				}
			}
		return fieldsChanged;}

/*i async*/UserManager.Login.prototype.saveToCollection = async function () {var _c_this = this; var _c_root_method_arguments = arguments;
/*async*/
		var fields = _c_this.getFieldsChanged();
		var update = _c_this.collection.update().where("id", "==", _c_this.id);
		for (var i = 0; i < fields.length; i++) {
			var field = fields[i];
			update.set(field.name, _c_this.getFieldValue(field.name));
			}
		return (await update.run/* async call */());}

/*i async*/UserManager.Login.prototype.loadFromMap = async function (data) {var _c_this = this; var _c_root_method_arguments = arguments;
		_c_this.rawFields = data;
		
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

UserManager.Login.prototype.loadCreated = function (value) {var _c_this = this; var _c_root_method_arguments = arguments;
		_c_this.created = new Websom.Time();
		_c_this.created.timestamp = value;}

UserManager.Login.getSchema = function (collection) {var _c_this = this; var _c_root_method_arguments = arguments;
		return collection.schema().field("user", "reference").field("created", "time").field("ip", "string").field("location", "string").field("success", "boolean").field("flagged", "boolean");}

UserManager.User = function () {var _c_this = this;
	this.rawFields = null;

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

	this.bio = "";

	this.nickname = "";

	this.social = [];

	this.role = "";

	this.created = null;

	this.lastLogin = null;

	this.lastBan = null;

	this.banned = false;

	this.verified = false;

	this.connected = false;

	this.connectedAdapter = "";

	this.locked = false;

	this.groups = [];

	this.loginAttempts = null;

	this.connections = null;

	this.rawFields = null;

	this.collection = null;

	this.id = "";

	if (arguments.length == 0) {

	}
else 	if (arguments.length == 0) {

	}

}

/*i async*/UserManager.User.prototype.load = async function () {var _c_this = this; var _c_root_method_arguments = arguments;
/*async*/
		var doc = (await _c_this.collection.document/* async call */(_c_this.id));
		(await _c_this.loadFromMap/* async call */(doc.data()));}

/*i async*/UserManager.User.prototype.loadEntityArray = async function (arr) {var _c_this = this; var _c_root_method_arguments = arguments;
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
			}}

UserManager.User.applySchema = function (collection) {var _c_this = this; var _c_root_method_arguments = arguments;
		_c_this.linkToCollection(collection);
		
			return this.getSchema(collection);
		
		}

UserManager.User.linkToCollection = function (collection) {var _c_this = this; var _c_root_method_arguments = arguments;
		
			collection.entityTemplate = this;
		
		}

UserManager.User.prototype.getFieldValue = function () {var _c_this = this; var _c_root_method_arguments = arguments;
	if (arguments.length == 1 && (typeof arguments[0] == 'string' || typeof arguments[0] == 'undefined' || arguments[0] === null)) {
		var field = arguments[0];
		
			return this[field];
		
		
	}
else 	if (arguments.length == 1 && (typeof arguments[0] == 'string' || typeof arguments[0] == 'undefined' || arguments[0] === null)) {
		var field = arguments[0];
		
			return this[field];
		
		
	}
}

UserManager.User.prototype.getFieldsChanged = function () {var _c_this = this; var _c_root_method_arguments = arguments;
	if (arguments.length == 0) {
		var fieldsChanged = [];
		for (var i = 0; i < _c_this.collection.appliedSchema.fields.length; i++) {
			var field = _c_this.collection.appliedSchema.fields[i];
			var realValue = null;
			var myValue = _c_this.getFieldValue(field.name);
			var rawValue = _c_this.rawFields[field.name];
			var isDifferent = false;
			if (field.type == "time") {
				var cast = myValue;
				if (cast == null) {
					realValue = null;
					}else{
						realValue = cast.timestamp;
					}
				isDifferent = realValue != rawValue;
				}else if (field.type == "reference") {
				var cast = myValue;
				if (cast != null) {
					realValue = cast.id;
					}
				isDifferent = realValue != rawValue;
				}else if (field.type == "array") {
				
					isDifferent = JSON.stringify(myValue) != JSON.stringify(rawValue);
				
				
				}else{
					realValue = myValue;
					isDifferent = realValue != rawValue;
				}
			if (isDifferent) {
				fieldsChanged.push(field);
				}
			}
		return fieldsChanged;
	}
else 	if (arguments.length == 0) {
		var fieldsChanged = [];
		for (var i = 0; i < _c_this.collection.appliedSchema.fields.length; i++) {
			var field = _c_this.collection.appliedSchema.fields[i];
			var realValue = null;
			var myValue = _c_this.getFieldValue(field.name);
			var rawValue = _c_this.rawFields[field.name];
			var isDifferent = false;
			if (field.type == "time") {
				var cast = myValue;
				if (cast == null) {
					realValue = null;
					}else{
						realValue = cast.timestamp;
					}
				isDifferent = realValue != rawValue;
				}else if (field.type == "reference") {
				var cast = myValue;
				if (cast != null) {
					realValue = cast.id;
					}
				isDifferent = realValue != rawValue;
				}else if (field.type == "array") {
				
					isDifferent = JSON.stringify(myValue) != JSON.stringify(rawValue);
				
				
				}else{
					realValue = myValue;
					isDifferent = realValue != rawValue;
				}
			if (isDifferent) {
				fieldsChanged.push(field);
				}
			}
		return fieldsChanged;
	}
}

/*i async*/UserManager.User.prototype.saveToCollection = async function () {var _c_this = this; var _c_root_method_arguments = arguments;
	if (arguments.length == 0) {
/*async*/
		var fields = _c_this.getFieldsChanged();
		var update = _c_this.collection.update().where("id", "==", _c_this.id);
		for (var i = 0; i < fields.length; i++) {
			var field = fields[i];
			update.set(field.name, _c_this.getFieldValue(field.name));
			}
		return (await update.run/* async call */());
	}
else 	if (arguments.length == 0) {
/*async*/
		var fields = _c_this.getFieldsChanged();
		var update = _c_this.collection.update().where("id", "==", _c_this.id);
		for (var i = 0; i < fields.length; i++) {
			var field = fields[i];
			update.set(field.name, _c_this.getFieldValue(field.name));
			}
		return (await update.run/* async call */());
	}
}

/*i async*/UserManager.User.prototype.loadFromMap = async function (data) {var _c_this = this; var _c_root_method_arguments = arguments;
		_c_this.rawFields = data;
		
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

UserManager.User.prototype.loadCreated = function (value) {var _c_this = this; var _c_root_method_arguments = arguments;
		_c_this.created = new Websom.Time();
		_c_this.created.timestamp = value;}

UserManager.User.prototype.loadLastLogin = function (value) {var _c_this = this; var _c_root_method_arguments = arguments;
		_c_this.lastLogin = new Websom.Time();
		_c_this.lastLogin.timestamp = value;}

UserManager.User.prototype.loadLastBan = function (value) {var _c_this = this; var _c_root_method_arguments = arguments;
		_c_this.lastBan = new Websom.Time();
		_c_this.lastBan.timestamp = value;}

UserManager.User.getSchema = function (collection) {var _c_this = this; var _c_root_method_arguments = arguments;
		return collection.schema().field("username", "string").field("email", "string").field("password", "string").field("firstName", "string").field("lastName", "string").field("department", "string").field("company", "string").field("address", "string").field("city", "string").field("state", "string").field("country", "string").field("postCode", "string").field("bio", "string").field("nickname", "string").field("social", "array").field("role", "string").field("created", "time").field("lastLogin", "time").field("lastBan", "time").field("banned", "boolean").field("verified", "boolean").field("connected", "boolean").field("connectedAdapter", "string").field("locked", "boolean").field("groups", "array");}

UserManager.GoogleConnection = function (server) {var _c_this = this;
	this.server = null;

		_c_this.server = server;
}

/*i async*/UserManager.GoogleConnection.prototype.getUser = async function (data) {var _c_this = this; var _c_root_method_arguments = arguments;
		var idToken = data["id_token"];
		var realData = {};
		var clientID = _c_this.server.getConfigString("adapter.connection.google", "clientID");
		
			const { OAuth2Client } = require("google-auth-library");

			const client = new OAuth2Client(clientID);

			try {
				let ticket = await client.verifyIdToken({
					idToken,
					audience: clientID
				});

				realData = ticket.getPayload();
			} catch(e) {
				return;
			}
		
		
		var firstName = realData["given_name"];
		var lastName = realData["family_name"];
		var email = realData["email"];
		var t = Websom.Time.now().toString();
		var username = firstName + "_" + lastName + "_" + t.substr(5,t.length);
		return new Websom.Adapters.UserSystem.ConnectionUser(firstName, lastName, username, email);}

/*i async*/UserManager.GoogleConnection.prototype.initialize = async function () {var _c_this = this; var _c_root_method_arguments = arguments;
}

/*i async*/UserManager.GoogleConnection.prototype.shutdown = async function () {var _c_this = this; var _c_root_method_arguments = arguments;
}


module.exports = UserManager.Module;