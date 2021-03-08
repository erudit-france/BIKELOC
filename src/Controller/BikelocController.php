<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class BikelocController extends AbstractController
{
    /**
     * @Route("/", name="bikeloc")
     */
    public function index(): Response
    {
        // var_dump(phpinfo());
        return $this->render('bikeloc/index.html.twig');
    }

    /**
     * @Route("/Vehicules", name="Vehicules")
     */
    public function vehicules()
    {
        return $this->render('bikeloc/Vehicules.html.twig');
    }

    /**
     * @Route("/produit", name="produit")
     */
    public function produit()
    {
        return $this->render('bikeloc/produit.html.twig');
    }

    /**
     * @Route("/panier", name="panier")
     */
    public function panier()
    {
        return $this->render('bikeloc/panier.html.twig');
    }
    
    /**
     * @Route("/services", name="services")
     */
    public function services()
    {
        return $this->render('bikeloc/services.html.twig');
    }

    /**
     * @Route("/checkCommande", name="checkCommande")
     */
    public function checkCommande()
    {
        return $this->render('bikeloc/checkCommande.html.twig');
    }


}
