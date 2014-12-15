function ImgClick(e){
        var evt = e ? e:window.event;
        var clickX=0, clickY=0;
        var pageX=0, pageY=0;
        if ((evt.clientX || evt.clientY) &&
            document.body &&
            document.body.scrollLeft!=null) {
         clickX = evt.clientX + document.body.scrollLeft;
         clickY = evt.clientY + document.body.scrollTop;
        }
        if ((evt.clientX || evt.clientY) &&
            document.compatMode=='CSS1Compat' && 
            document.documentElement && 
            document.documentElement.scrollLeft!=null) {
         clickX = evt.clientX + document.documentElement.scrollLeft;
         clickY = evt.clientY + document.documentElement.scrollTop;
        }
        if (evt.pageX || evt.pageY) {
         clickX = evt.pageX;
         clickY = evt.pageY;
        }


		if((clickX>430 && clickX<650) && (clickY>315 && clickY<400)  ){
		  window.location.assign("http://localhost:8080/attacks");
		}
		
		if((clickX>490 && clickX<600) && (clickY>470 && clickY<560)  ){
                      window.location.assign("http://localhost:8080/packets");
        }

        if((clickX>327 && clickX<400) && (clickY>647 && clickY<707)  ){
          window.location.assign("http://localhost:8080/packets-ip/10.0.0.1");
        } 

        if((clickX>506 && clickX<576) && (clickY>647 && clickY<707)  ){
          window.location.assign("http://localhost:8080/packets-ip/10.0.0.2");
        } 

        if((clickX>677 && clickX<747) && (clickY>647 && clickY<707)  ){
          window.location.assign("http://localhost:8080/packets-ip/10.0.0.3");
        } 		

        return false;
}

window.onload = function ()
    {	
		var img = document.getElementById("content");
		img.addEventListener("click", ImgClick, false);
    }