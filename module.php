<?php
//Relative Module
//Relative User
//Relative Login
//Relative Connection
class UserManager {

function __construct(...$arguments) {


}

}class UserManager_Module {
public $userCreate;

public $userGet;

public $loginView;

public $groupCounts;

public $server;

public $baseConfig;

public $containers;

public $bridges;

public $registeredCollections;

public $registeredPermissions;

public $name;

public $id;

public $root;

public $version;

public $author;

public $license;

public $repo;

public $users;

public $logins;

function __construct($server) {
$this->userCreate = null;
$this->userGet = null;
$this->loginView = null;
$this->groupCounts = null;
$this->server = null;
$this->baseConfig = null;
$this->containers = [];
$this->bridges = [];
$this->registeredCollections = [];
$this->registeredPermissions = [];
$this->name = "";
$this->id = "";
$this->root = "";
$this->version = "";
$this->author = "";
$this->license = "";
$this->repo = "";
$this->users = null;
$this->logins = null;

$this->server = $server;
$this->registerWithServer();
}
function start() {
$this->server->confirmation->handleConfirmation("emailVerification", function ($exec)  {$id = $exec->storage["id"];
$user = $this->users->getEntity($id);
$user->verified = true;
$user->saveToCollection();});
$this->server->confirmation->handleConfirmation("passwordReset", function ($exec)  {$id = $exec->storage["id"];
$user = $this->users->getEntity($id);
if ($exec->params == null or (gettype($exec->params) == 'double' ? 'float' : (gettype($exec->params) == 'array' ? (isset($exec->params['_c__mapC']) ? 'map' : 'array') : gettype($exec->params))) != "map") {
$exec->request->endWithError("Invalid params");
return null;}
$newPassword = $exec->params["password"];
if ((gettype($newPassword) == 'double' ? 'float' : (gettype($newPassword) == 'array' ? (isset($newPassword['_c__mapC']) ? 'map' : 'array') : gettype($newPassword))) == "string" and strlen($newPassword) > 3 and strlen($newPassword) < 256) {
$user->password = $this->server->crypto->hashPassword($newPassword);
$user->saveToCollection();}else{
$exec->request->endWithError("Invalid password");}});}

function registerWithServer() {
$this->server->userSystem = $this;}

function permissions() {
$this->userGet = new Websom_Permission("User.Get");
$this->userGet->description = "Allows the public to read users (username, and time created) querying on their id.";
$this->userGet->_c__public = true;
$this->userCreate = new Websom_Permission("User.Create");
$this->userCreate->description = "Allows the public to create a user account.";
$this->userCreate->_c__public = true;
$this->registerPermission($this->userCreate);
$this->registerPermission($this->userGet);
$this->loginView = new Websom_Permission("LoginAttempts.View");
$this->loginView->description = "Administrator view";
$this->registerPermission($this->loginView);}

function getUserFromRequest($req) {
$userId = $req->session->get("user");
if ($userId == null) {
return null;}
$user = $this->users->getEntity($userId);
return $user;}

function collections() {
$db = $this->server->database->central;
$this->users = $db->collection("users");
$this->groupCounts = new Websom_Calculators_KeyCount("groups", "array");
UserManager_User::applySchema($this->users)->calc("groupCounts", $this->groupCounts)->index()->field("name", "==")->field("created", "dsc");
$this->registerCollection($this->users);
$this->logins = $db->collection("logins");
UserManager_Login::applySchema($this->logins)->index()->field("user", "==")->field("created", "dsc");
$this->registerCollection($this->logins);
$this->server->api->_c__interface($this->logins, "/logins")->route("/search")->auth($this->loginView)->executes("select")->read("id")->read("user")->read("created")->read("id")->read("flagged")->read("success")->read("location")->read("ip")->filter("default")->filter("user")->field("user", "==");
$this->server->api->_c__interface($this->users, "/users")->route("/create")->auth($this->userCreate)->executes("insert")->write("username")->format("single-line")->regexTest("^([A-Za-z0-9_-]*)\$")->limit(3, 256)->unique()->write("password")->regexTest("^[ -~]*\$")->limit(8, 256)->mutate(function ($collection, $req, $value) use (&$db) {return $this->server->crypto->hashPassword($value);})->write("email")->format("email")->unique()->setComputed("created", function ($req) use (&$db) {return Websom_Time::now();})->set("banned", false)->set("verified", false)->set("locked", false)->set("connected", false)->set("connectedAdapter", "")->set("groups", [])->route("/get")->auth($this->userGet)->executes("select")->read("username")->read("created")->read("id")->read("bio")->read("social")->read("nickname")->filter("default")->field("id", "==")->route("user-info")->auth($this->userGet)->executes("select")->read("id")->read("username")->read("created")->read("email")->read("firstName")->read("lastName")->filter("default", function ($req, $query) use (&$db) {$userId = $req->session->get("user");
if ($userId == null) {
$req->endWithError("Not logged in");
return null;}
$query->where("id", "==", $userId);});
$this->server->api->route("/users/connection-sign-in")->auth($this->userCreate)->input("adapter")->type("string")->input("data")->type("map")->executes(function ($ctx) use (&$db) {$adapter = $ctx->get("adapter");
$data = &$ctx->get("data");
$this->handleConnectionSignin($ctx->request, $adapter, $data);});
$this->server->api->route("/logout")->executes(function ($ctx) use (&$db) {$ctx->request->session->delete("user");
$ctx->request->endWithSuccess("Signed out");});
$this->server->api->route("/login")->input("login")->type("string")->limit(3, 256)->input("password")->type("string")->limit(8, 256)->executes(function ($ctx) use (&$db) {$login = $ctx->get("login");
$password = $ctx->get("password");
$emailValidator = new Websom_Restrictions_Format("email");
$userResults = null;
if ($emailValidator->testServer(null, null, $login)) {
$userResults = $this->users->where("email", "==", $login)->get();}else{
$userResults = $this->users->where("username", "==", $login)->get();}
if (count($userResults->documents) == 0) {
$ctx->request->endWithError("Invalid username or password");
return null;}
$user = $this->users->makeEntity(_c_lib__arrUtils::readIndex($userResults->documents, 0));
$passedPassword = $this->server->crypto->verifyPassword($user->password, $password);
if ($user->verified == false) {
$mp = new _carb_map();
$mp["id"] = $user->id;
$ctx->request->endWithComponent("user-unverified-status", $mp);
return null;}
if ($user->connected) {
$ctx->request->endWithError("Please login using " . $user->connectedAdapter);
return null;}
if ($passedPassword) {
$this->logLogin($ctx->request->client->address, "", $user, true, false);
$ctx->request->session->set("user", $user->id);
$ctx->request->endWithSuccess("Login successful");}else{
$this->logLogin($ctx->request->client->address, "", $user, false, false);
$ctx->request->endWithError("Invalid username or password");}});
$this->server->api->route("/resend-verification-email")->input("id")->type("string")->limit(1, 255)->executes(function ($ctx) use (&$db) {$user = $this->users->getEntity($ctx->get("id"));
if ($user == null) {
$ctx->request->endWithError("Invalid id");
return null;}
if ($this->sendVerificationEmail($user)) {
$ctx->request->endWithSuccess("Verification sent");}else{
$ctx->request->endWithError("Error while sending verification");}});
$this->server->api->route("/reset-password")->input("email")->type("string")->format("email")->limit(1, 255)->executes(function ($ctx) use (&$db) {$email = $ctx->get("email");
$docs = $this->users->where("email", "==", $email)->get();
if (count($docs->documents) > 0) {
$doc = $this->users->makeEntity(_c_lib__arrUtils::readIndex($docs->documents, 0));
if ($this->sendPasswordReset($doc) == false) {
$ctx->request->endWithError("Error while sending password reset.");}}
$ctx->request->endWithSuccess("Password reset sent! Please check your inbox.");});}

function sendVerificationEmail($user) {
$mp = new _carb_map();
$mp["id"] = $user->id;
;
$this->server->confirmation->confirm("emailVerification")->via("email")->using("link")->to($user->email)->store($mp)->subject("Email verification")->message("Click here to finalize your account verification.")->dispatch();
return true;}

function sendPasswordReset($user) {
$mp = new _carb_map();
$mp["id"] = $user->id;
$this->server->confirmation->confirm("passwordReset")->via("email")->using("link")->to($user->email)->store($mp)->subject("Password Reset")->message("Click here to reset your password.")->dispatch();
return true;}

function logLogin($ip, $location, $user, $success, $flagged) {
$this->logins->insert()->set("created", Websom_Time::now())->set("ip", $ip)->set("location", $location)->set("user", $user->id)->set("success", $success)->set("flagged", $flagged)->run();}

function loginWithConnection($req, $adapter, $user) {
$this->logLogin($req->client->address, "", $user, true, false);
$req->session->set("user", $user->id);
$req->endWithSuccess("Login successful");}

function createUserWithConnection($req, $adapter, $user) {
$res = $this->users->insert()->set("username", $user->username)->set("firstName", $user->firstName)->set("lastName", $user->lastName)->set("password", "")->set("email", $user->email)->set("created", Websom_Time::now())->set("banned", false)->set("verified", true)->set("locked", false)->set("connected", true)->set("connectedAdapter", $adapter)->set("groups", [])->run();
$userEntity = new UserManager_User();
$userEntity->id = $res->id;
$userEntity->collection = $this->users;
$this->loginWithConnection($req, $adapter, $userEntity);}

function handleConnectionSignin($req, $adapter, $data) {
$adapterInterface = $this->server->adapt("connection");
if ($adapterInterface->loadAsBranchAdapter($adapter)) {
$cAdapter = $adapterInterface->adapter;
$user = $cAdapter->getUser($data);
if ($user == null) {
$req->endWithError("Authentication error");
return null;}
$userRes = $this->users->where("email", "==", $user->email)->get();
if (count($userRes->documents) == 0) {
$this->createUserWithConnection($req, $adapter, $user);}else{
$userEntity = $this->users->makeEntity(_c_lib__arrUtils::readIndex($userRes->documents, 0));
if ($userEntity->connected) {
if ($userEntity->connectedAdapter == $adapter) {
$this->loginWithConnection($req, $adapter, $userEntity);}else{
$req->endWithError("Please sign in through " . $adapter);
return null;}}else{
$req->endWithError("Please sign in using your email and password");
return null;}}}else{
$req->endWithError("Unknown adapter " . $adapter);}}

function clientData($req, $send) {
return false;}

function spawn($config) {
$this->baseConfig = $config;
$this->name = $config["name"];
$this->id = $config["id"];}

function stop() {
}

function configure() {
}

function registerCollection($collection) {
array_push($this->registeredCollections, $collection);
if ($this->server->config->dev) {
if ($collection->appliedSchema != null) {
$collection->appliedSchema->register();}}}

function registerPermission(...$arguments) {
if (count($arguments) == 1 and ((_c_lib_run::getClass($arguments[0]) == 'Websom_Permission') or gettype($arguments[0]) == 'NULL')) {
$permission = $arguments[0];
array_push($this->registeredPermissions, $permission);
}
else if (count($arguments) == 1 and (gettype($arguments[0]) == 'string' or gettype($arguments[0]) == 'NULL')) {
$permission = $arguments[0];
$perm = new Websom_Permission($permission);
array_push($this->registeredPermissions, $perm);
return $perm;
}
}

function setupData() {
}

function setupBridge() {
}

function pullFromGlobalScope($name) {
}

function &setupBridges() {
$bridges = [];
return $bridges;}


}//Relative Carbon
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
class UserManager_Login {
public $rawFields;

public $collection;

public $id;

public $user;

public $created;

public $ip;

public $location;

public $success;

public $flagged;

function __construct() {
$this->rawFields = null;
$this->collection = null;
$this->id = "";
$this->user = null;
$this->created = null;
$this->ip = "";
$this->location = "";
$this->success = false;
$this->flagged = false;


}
function load() {
$doc = $this->collection->document($this->id);
$this->loadFromMap($doc->data());}

function loadEntityArray($arr) {
if (count($arr) > 0) {
$collection = _c_lib__arrUtils::readIndex($arr, 0)->collection;
$ids = [];
for ($i = 0; $i < count($arr); $i++) {
array_push($ids, _c_lib__arrUtils::readIndex($arr, $i)->id);}
$docs = &$collection->getAll($ids);
for ($i = 0; $i < count($docs); $i++) {
$doc = _c_lib__arrUtils::readIndex($docs, $i);
$entity = _c_lib__arrUtils::find($arr, function ($ent) use (&$i, &$doc, &$entity, &$collection, &$ids, &$docs, &$arr) {return $ent->id == $doc->id;});
$entity->loadFromMap($doc->data());}}}

static function applySchema($collection) {
$this::linkToCollection($collection);


			return self::getSchema($collection);
		}

static function linkToCollection($collection) {


			$collection->entityTemplate = __CLASS__;
		}

function getFieldValue($field) {


			return $this->$field;
		}

function &getFieldsChanged() {
$fieldsChanged = [];
for ($i = 0; $i < count($this->collection->appliedSchema->fields); $i++) {
$field = _c_lib__arrUtils::readIndex($this->collection->appliedSchema->fields, $i);
$realValue = null;
$myValue = $this->getFieldValue($field->name);
$rawValue = $this->rawFields[$field->name];
$isDifferent = false;
if ($field->type == "time") {
$cast = $myValue;
if ($cast == null) {
$realValue = null;}else{
$realValue = $cast->timestamp;}
$isDifferent = $realValue != $rawValue;}else if ($field->type == "reference") {
$cast = $myValue;
if ($cast != null) {
$realValue = $cast->id;}
$isDifferent = $realValue != $rawValue;}else if ($field->type == "array") {


					$isDifferent = count(array_diff($myValue, $rawValue)) > 0;
				}else{
$realValue = $myValue;
$isDifferent = $realValue != $rawValue;}
if ($isDifferent) {
array_push($fieldsChanged, $field);}}
return $fieldsChanged;}

function saveToCollection() {
$fields = &$this->getFieldsChanged();
$update = $this->collection->update()->where("id", "==", $this->id);
for ($i = 0; $i < count($fields); $i++) {
$field = _c_lib__arrUtils::readIndex($fields, $i);
$update->set($field->name, $this->getFieldValue($field->name));}
return $update->run();}

function loadFromMap($data) {
$this->rawFields = $data;


			foreach ($data as $k => $v) {
				if (isset($this->$k)) {
					$camel = ucfirst($k);
					
					if (method_exists($this, "load" . $camel)) {
						$this->{"load" . $camel}($data[$k]);
					}else{
						$this->{$k} = $data[$k];
					}
				}
			}
		}

function loadCreated($value) {
$this->created = new Websom_Time();
$this->created->timestamp = $value;}

static function getSchema($collection) {
return $collection->schema()->field("user", "reference")->field("created", "time")->field("ip", "string")->field("location", "string")->field("success", "boolean")->field("flagged", "boolean");}


}class UserManager_User {
public $rawFields;

public $collection;

public $id;

public $username;

public $email;

public $password;

public $firstName;

public $lastName;

public $department;

public $company;

public $address;

public $city;

public $state;

public $country;

public $postCode;

public $bio;

public $nickname;

public $social;

public $role;

public $created;

public $lastLogin;

public $lastBan;

public $banned;

public $verified;

public $connected;

public $connectedAdapter;

public $locked;

public $groups;

public $loginAttempts;

public $connections;

public $rawFields;

public $collection;

public $id;

function __construct(...$arguments) {
$this->rawFields = null;
$this->collection = null;
$this->id = "";
$this->username = "";
$this->email = "";
$this->password = "";
$this->firstName = "";
$this->lastName = "";
$this->department = "";
$this->company = "";
$this->address = "";
$this->city = "";
$this->state = "";
$this->country = "";
$this->postCode = "";
$this->bio = "";
$this->nickname = "";
$this->social = [];
$this->role = "";
$this->created = null;
$this->lastLogin = null;
$this->lastBan = null;
$this->banned = false;
$this->verified = false;
$this->connected = false;
$this->connectedAdapter = "";
$this->locked = false;
$this->groups = [];
$this->loginAttempts = null;
$this->connections = null;
$this->rawFields = null;
$this->collection = null;
$this->id = "";

if (count($arguments) == 0) {

}
else if (count($arguments) == 0) {

}

}
function load() {
$doc = $this->collection->document($this->id);
$this->loadFromMap($doc->data());}

function loadEntityArray($arr) {
if (count($arr) > 0) {
$collection = _c_lib__arrUtils::readIndex($arr, 0)->collection;
$ids = [];
for ($i = 0; $i < count($arr); $i++) {
array_push($ids, _c_lib__arrUtils::readIndex($arr, $i)->id);}
$docs = &$collection->getAll($ids);
for ($i = 0; $i < count($docs); $i++) {
$doc = _c_lib__arrUtils::readIndex($docs, $i);
$entity = _c_lib__arrUtils::find($arr, function ($ent) use (&$i, &$doc, &$entity, &$collection, &$ids, &$docs, &$arr) {return $ent->id == $doc->id;});
$entity->loadFromMap($doc->data());}}}

static function applySchema($collection) {
$this::linkToCollection($collection);


			return self::getSchema($collection);
		}

static function linkToCollection($collection) {


			$collection->entityTemplate = __CLASS__;
		}

function getFieldValue(...$arguments) {
if (count($arguments) == 1 and (gettype($arguments[0]) == 'string' or gettype($arguments[0]) == 'NULL')) {
$field = $arguments[0];


			return $this->$field;
		
}
else if (count($arguments) == 1 and (gettype($arguments[0]) == 'string' or gettype($arguments[0]) == 'NULL')) {
$field = $arguments[0];


			return $this->$field;
		
}
}

function &getFieldsChanged(...$arguments) {
if (count($arguments) == 0) {
$fieldsChanged = [];
for ($i = 0; $i < count($this->collection->appliedSchema->fields); $i++) {
$field = _c_lib__arrUtils::readIndex($this->collection->appliedSchema->fields, $i);
$realValue = null;
$myValue = $this->getFieldValue($field->name);
$rawValue = $this->rawFields[$field->name];
$isDifferent = false;
if ($field->type == "time") {
$cast = $myValue;
if ($cast == null) {
$realValue = null;}else{
$realValue = $cast->timestamp;}
$isDifferent = $realValue != $rawValue;}else if ($field->type == "reference") {
$cast = $myValue;
if ($cast != null) {
$realValue = $cast->id;}
$isDifferent = $realValue != $rawValue;}else if ($field->type == "array") {


					$isDifferent = count(array_diff($myValue, $rawValue)) > 0;
				}else{
$realValue = $myValue;
$isDifferent = $realValue != $rawValue;}
if ($isDifferent) {
array_push($fieldsChanged, $field);}}
return $fieldsChanged;
}
else if (count($arguments) == 0) {
$fieldsChanged = [];
for ($i = 0; $i < count($this->collection->appliedSchema->fields); $i++) {
$field = _c_lib__arrUtils::readIndex($this->collection->appliedSchema->fields, $i);
$realValue = null;
$myValue = $this->getFieldValue($field->name);
$rawValue = $this->rawFields[$field->name];
$isDifferent = false;
if ($field->type == "time") {
$cast = $myValue;
if ($cast == null) {
$realValue = null;}else{
$realValue = $cast->timestamp;}
$isDifferent = $realValue != $rawValue;}else if ($field->type == "reference") {
$cast = $myValue;
if ($cast != null) {
$realValue = $cast->id;}
$isDifferent = $realValue != $rawValue;}else if ($field->type == "array") {


					$isDifferent = count(array_diff($myValue, $rawValue)) > 0;
				}else{
$realValue = $myValue;
$isDifferent = $realValue != $rawValue;}
if ($isDifferent) {
array_push($fieldsChanged, $field);}}
return $fieldsChanged;
}
}

function saveToCollection(...$arguments) {
if (count($arguments) == 0) {
$fields = &$this->getFieldsChanged();
$update = $this->collection->update()->where("id", "==", $this->id);
for ($i = 0; $i < count($fields); $i++) {
$field = _c_lib__arrUtils::readIndex($fields, $i);
$update->set($field->name, $this->getFieldValue($field->name));}
return $update->run();
}
else if (count($arguments) == 0) {
$fields = &$this->getFieldsChanged();
$update = $this->collection->update()->where("id", "==", $this->id);
for ($i = 0; $i < count($fields); $i++) {
$field = _c_lib__arrUtils::readIndex($fields, $i);
$update->set($field->name, $this->getFieldValue($field->name));}
return $update->run();
}
}

function loadFromMap($data) {
$this->rawFields = $data;


			foreach ($data as $k => $v) {
				if (isset($this->$k)) {
					$camel = ucfirst($k);
					
					if (method_exists($this, "load" . $camel)) {
						$this->{"load" . $camel}($data[$k]);
					}else{
						$this->{$k} = $data[$k];
					}
				}
			}
		}

function loadCreated($value) {
$this->created = new Websom_Time();
$this->created->timestamp = $value;}

function loadLastLogin($value) {
$this->lastLogin = new Websom_Time();
$this->lastLogin->timestamp = $value;}

function loadLastBan($value) {
$this->lastBan = new Websom_Time();
$this->lastBan->timestamp = $value;}

static function getSchema($collection) {
return $collection->schema()->field("username", "string")->field("email", "string")->field("password", "string")->field("firstName", "string")->field("lastName", "string")->field("department", "string")->field("company", "string")->field("address", "string")->field("city", "string")->field("state", "string")->field("country", "string")->field("postCode", "string")->field("bio", "string")->field("nickname", "string")->field("social", "array")->field("role", "string")->field("created", "time")->field("lastLogin", "time")->field("lastBan", "time")->field("banned", "boolean")->field("verified", "boolean")->field("connected", "boolean")->field("connectedAdapter", "string")->field("locked", "boolean")->field("groups", "array");}


}class UserManager_GoogleConnection {
public $server;

function __construct($server) {
$this->server = null;

$this->server = $server;
}
function getUser($data) {
$idToken = $data["id_token"];
$realData = new _carb_map();
$clientID = $this->server->getConfigString("adapter.connection.google", "clientID");


			$client = new Google_Client([
				"client_id" => $clientID
			]);

			$realData = $client->verifyIdToken($id_token);

			if (!$realData)
				return;
		
$firstName = $realData["given_name"];
$lastName = $realData["family_name"];
$email = $realData["email"];
$t = strval(Websom_Time::now());
$username = $firstName . "_" . $lastName . "_" . substr($t, 5,strlen($t));
return new Websom_Adapters_UserSystem_ConnectionUser($firstName, $lastName, $username, $email);}

function initialize() {
}

function shutdown() {
}


}
?>
<?php return 'UserManager_Module'; ?>