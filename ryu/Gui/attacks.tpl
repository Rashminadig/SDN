%#template to generate a HTML table from a list of tuples (or list of lists, or tuple of tuples or ...)
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8" />
	<title>SDN DETECTIVE</title>
	
	<link rel="stylesheet" href="main.css" type="text/css" />
	<meta http-equiv="refresh" content="30">
</head>
 
<body id="index" class="home">
 
	<header id="banner" class="body">
                <h1><img src="security_guard_icon_mod.png" alt="Logo" class="photo" />
                <a href="/">SDN DETECTIVE <strong>IDS system using RYU controller</strong></a></h1>		
	 
		<nav><ul>
			<li ><a href="/">Home</a></li>
			<li><a href="/packets">Traffic</a></li>
			<li class="active"><a href="/attacks">Attacks</a></li>
			<li><a href="/action">Action</a></li>
			<li><a href="/rules">Rules</a></li>
		</ul></nav>
	 
	</header><!-- /#banner -->	
	
	<section id="content" class="body">
		<header>
			<h2 class="entry-title">The Packets received by IDS-controller are as follows:</h2>
 
		</header>
		<section class="table_section">
			<table border="1" id= "attacks-list">
				  <tr>
				    <th>Attack Name</th>
				    <th>Protocol</th>
				    <th>Message</th>
				    <th>Source IP Address</th>
				    <th>Source Port</th>
				    <th>Destination IP Address</th>
				    <th>Destination Port</th>
				  </tr>
				%for row in rows:
				  <tr>
				    <td>{{row[1]}}</td>
				    <td>{{row[2]}}</td>
				    <td>{{row[3]}}</td>
				    <td>{{row[4]}}</td>
				    <td>{{row[6]}}</td>
				    <td>{{row[5]}}</td>
				    <td>{{row[7]}}</td>
				  %end
				  </tr>
				%end
			</table>
		</section>
		<footer class="filter">
            <form action="/attacks_filter" method="post">
                          
                <select class = "filter_type"  name="filter_name">
				  <option value="protocol">Protocol</option>
				  <option value="sourceip">Source Ip Address</option>
				  <option value="destip">Destination IP Address</option>
				  <option value="sourceport">Source Port Number</option>
				  <option value="destport">Destination Port Number</option>
			     </select>
			     <input class = "filter_p" type="text" name="filter_param">
			     <input class="button" type="submit">
			</form>
		</footer>
	 
				
	</section><!-- /#content --> 
</body>
</html>
