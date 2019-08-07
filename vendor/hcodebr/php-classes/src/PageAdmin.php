<?php
namespace Hcode;
use Rain\Tpl;
use \Hcode\Model\User;


class PageAdmin extends Page {

    public function __construct($opts = array(), $tpl_dir = "/views/admin/"){
        $user = User::getFromSession();
        if ($user) {
            if (!isset($opts['data'])) {
                $opts['data'] = array();
            }
            $opts['data']['name'] = $user->getdeslogin();
            $opts['data']['user'] = $user;
        }
        parent::__construct($opts, $tpl_dir);
    }

}
