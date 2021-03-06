<?php
namespace Hcode\Model;
use \Hcode\DB\Sql;
use \Hcode\Model;
use Facebook\Facebook;
use Hcode\Mailer;

require_once('Facebook/autoload.php');
require_once('Facebook/Facebook.php');

class User extends Model {

    const SESSION = "User";
    const SECRET = "mauricio99431";
    const SECRET_IV = "mauriciomauricio";
    const ERROR = "UserError";
    const ERROR_REGISTER = "UserErrorRegister";
    const SUCCESS = "UserSucess";

    protected $fields = [
		"iduser", "idperson", "deslogin", "despassword", "inadmin",  "desperson", "desemail"
	];
    
    
    public static function getFromSession() {
        $user = new User();
        if (isset($_SESSION[User::SESSION]) && (int)$_SESSION[User::SESSION]['iduser'] > 0) {
            $user->setData($_SESSION[User::SESSION]);
        }
        return $user;
    }

    public static function checkLogin($inadmin = true) {
        if (!isset($_SESSION[User::SESSION]) || !$_SESSION[User::SESSION] || !(int)$_SESSION[User::SESSION]["iduser"] > 0 ) {
            //Não está logado
            return false;
        } else {
            if ($inadmin === true && (bool)$_SESSION[User::SESSION]['inadmin'] === true){ 
                return true;
            } else if ($inadmin === false){
                return true;
            } else {
                return false;
            }
        }
    }

    public static function login($login, $password){
	
		$sql = new Sql();
		$results = $sql->select("SELECT * FROM tb_users a INNER JOIN tb_persons b ON a.idperson = b.idperson WHERE a.deslogin = :LOGIN", array(
			":LOGIN"=>$login
		)); 
		if (count($results) === 0)
		{
			throw new \Exception("Usuário inexistente ou senha inválida.");
		}
		$data = $results[0];
		if (password_verify($password, $data["despassword"]) === true)
		{
			$user = new User();
			$data['desperson'] = utf8_encode($data['desperson']);
			$user->setData($data);
			$_SESSION[User::SESSION] = $user->getValues();
			return $user;
		} else {
			throw new \Exception("Usuário inexistente ou senha inválida.");
		}
	}

    public static function verifyLogin($inadmin = true) {
        if (!User::checkLogin($inadmin)) {
            if($inadmin) {
                header("Location: /admin/login");
            } else {
                header("Location: /login");
            }
            exit;
        }    
    } 

    public static function logout() {
        $_SESSION[User::SESSION] = NULL;
        
    }

    public static function facebook(){
    

        $fb = new Facebook ([
            'app_id' => '464306704395418',
            'app_secret' => '43327e13ede9f4842353b2a9d062c324',
            'default_graph_version' => 'v2.2',
            ]);
        
            $Logiin = $fb->getRedirectLoginHelper();



            $permissions = ['email'];


        try {
            if (isset($_SESSION['facebook_access_token'])) {
                $accessToken = $_SESSION['facebook_access_token'];
            } else {
                $accessToken = $Logiin->getAccessToken();
            }
        } catch (vendor\facebook\graphsdk\src\Facebook\Exceptions\FacebookResponseException $e) {
            echo 'Graph returned an error: ' . $e->getMessage();
            exit;
        } catch (vendor\facebook\graphsdk\src\Facebook\Exceptions\FacebookSDKException $e) {
            echo 'Facebook SDK returned an error: ' . $e->getMessage();
            exit;
        }
        if (isset($accessToken)) {
            if (isset($_SESSION['facebook_access_token'])) {
                $fb->setDefaultAccessToken($_SESSION['facebook_access_token']);
            } else {
                $_SESSION['facebook_access_token'] = (string) $accessToken;
                $oAuth2Client = $fb->getOAuth2Client();
                $longLivedAccessToken = $oAuth2Client->getLongLivedAccessToken($_SESSION['facebook_access_token']);
                $_SESSION['facebook_access_token'] = (string) $longLivedAccessToken;
                $fb->setDefaultAccessToken($_SESSION['facebook_access_token']);
            }
            if (isset($_GET['code'])) {
                header('Location: ./');
            }
            try {
                $profile_request = $fb->get('/me?fields=name,first_name,last_name,email');
                $profile = $profile_request->getGraphNode()->asArray();
            } catch (vendor\facebook\graphsdk\src\Facebook\Exceptions\FacebookResponseException $e) {
                echo 'Graph returned an error: ' . $e->getMessage();
                session_destroy();
                header("Location: ./");
                exit;
            } catch (vendor\facebook\graphsdk\src\Facebook\Exceptions\FacebookSDKException $e) {
                echo 'Facebook SDK returned an error: ' . $e->getMessage();
                exit;
            }
            var_dump($profile);
            $logoff = filter_input(INPUT_GET, 'sair', FILTER_DEFAULT);
            if (isset($logoff) && $logoff == 'true'):
                session_destroy();
                header("Location: ./");
            endif;
            echo '<a href="?sair=true">Sair</a>';
            var_dump($_SESSION);
        }else {
            $loginUrl = $Logiin->getLoginUrl('http://www.blackecommerce.com.br/admin/logiin/facebook', $permissions);
            echo '<a href="' . $loginUrl . '">Entrar com facebook</a>';
            echo $accessToken;
            var_dump($_SESSION);
        }

    }

    public static function listAll()
    {

        $sql = new Sql();
        return $sql->select("SELECT * FROM tb_users a INNER JOIN tb_persons b USING(idperson) ORDER BY b.desperson");
    
 
    }

    /*public function getdeslogin() {
        
        return $this->getValues()['deslogin'];
    }*/

    public function save()
    {

        $sql= new Sql();
        
        $results = $sql->select("CALL sp_users_save(:desperson, :deslogin, :despassword, :desemail, :nrphone, :inadmin)", array (
            ":desperson"=>utf8_decode($this->getdesperson()),
            ":deslogin"=>$this->getdeslogin(),
            ":despassword"=>User::getPasswordHash($this->getdespassword()),
            ":desemail"=>$this->getdesemail(),
            ":nrphone"=>$this->getnrphone(),
            ":inadmin"=>$this->getinadmin()
        
        ));

        $this->setData($results[0]);

    }

    public function get($iduser) {
        $sql = new Sql();
        $results = $sql->select("SELECT * FROM tb_users a INNER JOIN tb_persons b USING(idperson) WHERE a.iduser = :iduser", array(
            ":iduser"=>$iduser
        ));
        $data = $results[0];
       

        $data['desperson'] = utf8_encode($data['desperson']);

        $this->setData($data);
    }

    public function update() {
        $sql = new Sql();
        $results = $sql->select("CALL sp_usersupdate_save(:iduser, :desperson, :deslogin, :despassword, :desemail, :nrphone, :inadmin)", array (
            ":iduser"=>$this->getiduser(),
            ":desperson"=>utf8_decode($this->getdesperson()),
            ":deslogin"=>$this->getdeslogin(),
            ":despassword"=>User::getPasswordHash($this->getdespassword()),
            ":desemail"=>$this->getdesemail(),
            ":nrphone"=>$this->getnrphone(),
            ":inadmin"=>$this->getinadmin()
        
        ));
        var_dump($results);
        $this->setData($results[0]);

    }

    public function delete() {
        $sql = new Sql ();
        $sql->query("DELETE FROM tb_users WHERE iduser = :iduser
        ", array(
            ":iduser"=>$this->getiduser()
        ));
    }
    
    public static function getForgot($email, $inadmin = true) {

        $sql = new Sql();
       
        $results = $sql->select("SELECT 
            *
        FROM tb_persons a
        INNER JOIN tb_users b USING(idperson)
        WHERE 
            a.desemail = :email;
        "
        , array(
            ":email"=>$email
        ));
        if (count($results) === 0) {
            throw new Exception("Não foi possível recuperar a senha.");
        } else {
            $data = $results[0];
            $results2 = $sql->select("CALL sp_userspasswordsrecoveries_create(:iduser, :desip)",
            array(
                ":iduser"=>$data['iduser'],
                ":desip"=>$_SERVER['REMOTE_ADDR']
            ));
                

            if (count($results2) === 0)
            {
                throw new Exception("Não foi possível recuperar senha.");
            }
            else
            {
                $dataRecovery = $results2[0];
				$code = openssl_encrypt($dataRecovery['idrecovery'], 'AES192', User::SECRET, $options = 0, User::SECRET_IV);
                $code = base64_encode($code);
                    
				if ($inadmin === true) {
					$link = "http://www.blackecommerce.com.br/admin/forgot/reset?code=$code";
				} else {
					$link = "http://www.blackecommerce.com.br/forgot/reset?code=$code";
					
				}				
				$mailer = new Mailer($data['desemail'], $data['desperson'], "Redefinir senha da Black Store", "forgot", array(
					"name"=>$data['desperson'],
					"link"=>$link
				));				
				$mailer->send();
				return $link;
            }

        }

    }

    public static function validForgotDecrypt($code) {
                        
        $code = base64_decode($code);
		$idrecovery = openssl_decrypt($code, 'AES192', User::SECRET, $options = 0 , User::SECRET_IV);
                        
         

        $sql = new Sql();

       $results = $sql->select  
      ("     SELECT * 
            FROM db_ecommerce.tb_userspasswordsrecoveries a
            INNER JOIN tb_users n USING(iduser)
            INNER JOIN tb_persons c USING(idperson)
            WHERE
            a.idrecovery = :idrecovery
            AND
            a.dtrecovery is NULL
            AND
            DATE_ADD(a.dtregister, INTERVAL 1 HOUR) >= NOW();
        ", array(
        
            ":idrecovery"=>$idrecovery

        ));
            
          
       
        if (count($results) === 0)
        {

            throw new \Exception("Não foi possivel recuperar a senha!");
            
        } 
      
        else{

          return $results[0];

        }
      
    }

    public static function setFogotUsed($idrecovery) {
         $sql = new Sql();
         $sql->query("UPDATE tb_userspasswordsrecoveries SET dtrecovery = NOW() WHERE idrecovery = :idrecovery", array(
             ":idrecovery"=>$idrecovery
         ));
    }

    public function setPassword($password) {
         $sql = new Sql();
         $sql->query("UPDATE tb_users SET despassword = :password WHERE iduser = :iduser", array(
             ":password"=>$password,
             ":iduser"=>$this->getiduser()
         ));
    }

	public static function getPasswordHash($password) {
		return password_hash($password, PASSWORD_DEFAULT, [
			'cost'=>12
		]);
    }
    
    public static function setError($msg){
        $_SESSION[User::ERROR] = $msg;
    }


    public static function getError(){
        $msg = (isset($_SESSION[User::ERROR]) && $_SESSION[User::ERROR]) ? $_SESSION[User::ERROR] : "";
        User::clearError();
        return $msg;
    }

    public static function clearError(){
        $_SESSION[User::ERROR] = NULL;
    }

    public function setErrorRegister($msg){
    
       $_SESSION[User::ERROR_REGISTER] = $msg;
    }

    public static function getErrorRegister(){
        $msg = (isset($_SESSION[User::ERROR_REGISTER]) && $_SESSION[User::ERROR_REGISTER]) ? $_SESSION[User::ERROR_REGISTER] : '';
        User::clearErrorRegister();
        return $msg;
    }

    public static function clearErrorRegister(){
        $_SESSION[User::ERROR_REGISTER] = NULL;
    }
    
    public static function checkLoginExist($login){
        $sql = new Sql();
        $results = $sql->select("SELECT * FROM tb_users WHERE deslogin = :deslogin", [
            ':deslogin'=>$login
        ]);
        return (count($results) > 0);
    }

    public static function setSuccess($msg){
        $_SESSION[User::SUCCESS] = $msg;
    }


    public static function getSuccess(){
        $msg = (isset($_SESSION[User::SUCCESS]) && $_SESSION[User::SUCCESS]) ? $_SESSION[User::SUCCESS] : "";
        User::clearSuccess();
        return $msg;
    }

    public static function clearSuccess(){
        $_SESSION[User::SUCCESS] = NULL;
    }

    public function getOrders(){
        $sql = new Sql();
        $results = $sql->select("
			SELECT * 
			FROM tb_orders a 
			INNER JOIN tb_ordersstatus b USING(idstatus) 
			INNER JOIN tb_carts c USING(idcart)
			INNER JOIN tb_users d ON d.iduser = a.iduser
			INNER JOIN tb_addresses e USING(idaddress)
			INNER JOIN tb_persons f ON f.idperson = d.idperson
			WHERE a.iduser = :iduser
		", [
			':iduser'=>$this->getiduser()
        ]);
        return $results;
    }

    public static function getPage($page = 1, $itemsPerPage = 10){
        $start = ($page - 1) * $itemsPerPage;
        $sql = new Sql();
        $results = $sql->select(
            "SELECT SQL_CALC_FOUND_ROWS *
            FROM tb_users a INNER JOIN tb_persons b USING(idperson) ORDER BY b.desperson
            LIMIT $start, $itemsPerPage;"
        );
        $resultTotal = $sql->select("SELECT FOUND_ROWS() AS nrtotal; ");
        return [
            'data'=>$results, 
            'total'=>(int)$resultTotal[0]["nrtotal"],
            'pages'=>ceil($resultTotal[0]["nrtotal"] / $itemsPerPage)
        ];
       
    }

    public static function getPageSearch($search, $page = 1, $itemsPerPage = 10){
        $start = ($page - 1) * $itemsPerPage;
        $sql = new Sql();
        $results = $sql->select(
            "SELECT SQL_CALC_FOUND_ROWS *
            FROM tb_users a
            INNER JOIN tb_persons b USING(idperson) 
            WHERE b.desperson LIKE :search OR b.desemail = :search OR a.deslogin LIKE :search
            ORDER BY b.desperson
            LIMIT $start, $itemsPerPage;", [
                ':search'=>'%'.$search.'%'
            ]
        );
        $resultTotal = $sql->select("SELECT FOUND_ROWS() AS nrtotal; ");
        return [
            'data'=>$results, 
            'total'=>(int)$resultTotal[0]["nrtotal"],
            'pages'=>ceil($resultTotal[0]["nrtotal"] / $itemsPerPage)
        ];
       
    }
}