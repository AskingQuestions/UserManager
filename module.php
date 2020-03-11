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
$this->server->confirmation->handleConfirmation("emailVerification", function ($exec)  {;});}

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
$this->server->api->_c__interface($this->logins, "/logins")->route("/search")->auth($this->loginView)->executes("select")->read("user")->read("created")->read("id")->read("flagged")->read("success")->read("location")->read("ip")->filter("default")->filter("user")->field("user", "==");
$this->server->api->_c__interface($this->users, "/users")->route("/create")->auth($this->userCreate)->executes("insert")->write("username")->format("single-line")->regexTest("^([A-Za-z0-9_-]*)\$")->limit(3, 256)->unique()->write("password")->regexTest("^[ -~]*\$")->limit(8, 256)->mutate(function ($collection, $req, $value) use (&$db) {return $this->server->crypto->hashPassword($value);})->write("email")->format("email")->unique()->setComputed("created", function ($req) use (&$db) {return Websom_Time::now();})->set("banned", false)->set("verified", false)->set("locked", false)->set("connected", false)->set("groups", [])->route("/get")->auth($this->userGet)->executes("select")->read("username")->read("created")->filter("default");
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
$ctx->request->endWithError("Error while sending verification");}});}

function sendVerificationEmail($user) {
$mp = new _carb_map();
$mp["id"] = $user->id;
;
$this->server->confirmation->confirm("emailVerification")->via("email")->using("link")->to($user->email)->store($mp)->subject("Email verification")->message("Click here to finalize your account verification.")->dispatch();
return true;}

function logLogin($ip, $location, $user, $success, $flagged) {
$this->logins->insert()->set("created", Websom_Time::now())->set("ip", $ip)->set("location", $location)->set("user", $user->id)->set("success", $success)->set("flagged", $flagged)->run();}

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
public $collection;

public $id;

public $user;

public $created;

public $ip;

public $location;

public $success;

public $flagged;

function __construct() {
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

function loadFromMap($data) {


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

static function getSchema($collection) {
return $collection->schema()->field("user", "string")->field("created", "string")->field("ip", "string")->field("location", "string")->field("success", "string")->field("flagged", "string");}


}class UserManager_User {
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

public $role;

public $created;

public $lastLogin;

public $lastBan;

public $banned;

public $verified;

public $connected;

public $locked;

public $groups;

public $loginAttempts;

public $connections;

public $collection;

public $id;

function __construct(...$arguments) {
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
$this->role = "";
$this->created = null;
$this->lastLogin = null;
$this->lastBan = null;
$this->banned = false;
$this->verified = false;
$this->connected = false;
$this->locked = false;
$this->groups = [];
$this->loginAttempts = null;
$this->connections = null;
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

function loadFromMap($data) {


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

static function getSchema($collection) {
return $collection->schema()->field("username", "string")->field("email", "string")->field("password", "string")->field("firstName", "string")->field("lastName", "string")->field("department", "string")->field("company", "string")->field("address", "string")->field("city", "string")->field("state", "string")->field("country", "string")->field("postCode", "string")->field("role", "string")->field("created", "string")->field("lastLogin", "string")->field("lastBan", "string")->field("banned", "string")->field("verified", "string")->field("connected", "string")->field("locked", "string")->field("groups", "string");}


}
?>
<?php return 'UserManager_Module'; ?>