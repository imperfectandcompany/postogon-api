<?php
class DB {

	public function __construct($host, $dbname, $username, $password) {
		
		$pdo = new PDO('mysql:host='.$host.';dbname='.$dbname.';charset=utf8', $username, $password);
//then we tell pdo which password
		$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		$this->pdo = $pdo;
	}
	
	public function query($query, $params = array()) {
		$statement = $this->pdo->prepare($query);
		$statement->execute($params);
		
		//if the first keyword in the query is select, then run this.
		if (explode(' ', $query)[0] == 'SELECT'){
		$data = $statement->fetchAll();
		return $data;			
		}
	}

	

}