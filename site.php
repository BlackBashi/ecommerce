<?php

use \Hcode\PageAdmin;
use \Hcode\Page;

$app->get('/', function() {
	
    $page = new Page();

    $page->setTpl("index");

});

?>