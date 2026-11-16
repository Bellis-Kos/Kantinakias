package gr.hua.courier; 

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

//Diaxeirisi aitimatwn pou aforoun to courier service
@RestController
public class CourierController {
    
    //Endpoint gia ton elegxo diathesimotitas tou courier service
    @GetMapping("/courier/status")
    public String getStatus() {
        return "Courier service is running!";
    }
}