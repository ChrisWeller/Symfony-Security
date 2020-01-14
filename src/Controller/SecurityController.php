<?php
namespace PrimeSoftware\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

abstract class SecurityController extends AbstractController
{
    /**
     * @Route("/login", name="login")
     */
    public function login(): Response
    {
	    /**
	     * @var $user User
	     */
	    $user = $this->getUser();

	    if ( $user == null ) {
		    return new JsonResponse([
			    'status' => 'Fail',
		    ]);
	    }

	    $user->setApiToken( uniqid("S", true ) );
	    $em = $this->getDoctrine()->getManager();
	    $em->persist( $user );
	    $em->flush();

	    return new JsonResponse([
		    'status' => 'OK',
		    'token' => $user->getApiToken(),
		    'user' => $user,
	    ]);
    }

	/**
	 * @Route("/logout", name="app_logout", methods={"GET"})
	 */
	public function logout()
	{
		// controller can be blank: it will never be executed!
		throw new \Exception('Don\'t forget to activate logout in security.yaml');
	}
}
