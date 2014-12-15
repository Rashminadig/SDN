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
	
                        <li><a href="/packets">Traffic</a></li>
			<li><a href="/attacks">Attacks</a></li>
			<li class="active"><a href="/">Action</a></li> 
			<li><a href="/rules">Rules</a></li>
		</ul></nav>
	 
	</header><!-- /#banner -->	
	
	<section id="content" class="body">
		<header>
			<h2 class="entry-title">This Page displays Packet Action:</h2>
		</header>
		<section class="table_section">
			<table border="1" id= "attacks-list">  
				  <tr>
				    <th>Protocol</th>
				    <th>Source MAC Address</th>
				    <th>Source Ip Address</th>
				    <th>Destination MAC Address</th>
				    <th>Destination IP Address</th>
				    <th>Options</th>
				    <th>Packet Type</th>	
				    <th>Action Taken</th>	
				  </tr>
				%for row in rows:
				  <tr>
				    <td>{{row[1]}}</td>
				    <td>{{row[2]}}</td>
				    <td>{{row[4]}}</td>
				    <td>{{row[3]}}</td>
				    <td>{{row[5]}}</td>
				    <td>{{row[8]}}</td>
				    <td>{{row[9]}}</td>
				    <td>{{row[10]}}</td>
				  %end
				  </tr>
				%end
			</table>
		</section>
			 
				
	</section><!-- /#content --> 
</body>
</html>
