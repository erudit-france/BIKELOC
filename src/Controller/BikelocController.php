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
        return $this->render('bikeloc/index.html.twig', [
            'controller_name' => 'BikelocController',
        ]);
    }
}
