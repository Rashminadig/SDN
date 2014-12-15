%#template to generate a HTML table from a list of tuples (or list of lists, or tuple of tuples or ...)
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8" />
	<title>SDN DETECTIVE</title>
	
	<link rel="stylesheet" href="http://localhost:8080/main.css" />
	<meta http-equiv="refresh" content="30">
</head>
 
<body id="index" class="home">
 
	<header id="banner" class="body">
		<h1><img src="http://localhost:8080/security_guard_icon_mod.png" alt="Logo" class="photo" />
		<a href="/">SDN DETECTIVE <strong>IDS system using RYU controller</strong></a></h1>
	 
		<nav><ul>
			<li ><a href="/">Home</a></li>
			<li ><a href="/">Traffic</a></li>
	 
			<li><a href="/attacks">Attacks</a></li>
			<li><a href="/rules">Rules</a></li>
		</ul></nav>
	 
	</header><!-- /#banner -->	
	
	<section id="content" class="body">
		<header>
			<h2 class="error">Sorry no results found</h2>
		</header>
		<section>
             <form action={{back_url}} method="get">
                   <button class ="button backButton">Go Back</button>

             </form>
		</section>
	 
				
	</section><!-- /#content --> 
</body>
</html>
