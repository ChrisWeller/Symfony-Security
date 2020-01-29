<?php
namespace PrimeSoftware\Controller;

use App\Entity\User;
use PrimeSoftware\Service\EmailService;
use PrimeSoftware\Service\PreferenceService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

abstract class SecurityController extends AbstractController
{

	protected $userClassName = "User";

	/**
	 * @var EntityManagerInterface
	 */
	private $em;

	/**
	 * Holds the email service
	 * @var EmailService
	 */
	private $email_service;

	/**
	 * Holds the preferences service
	 * @var PreferenceService
	 */
	private $preferences;

	public function __construct( EntityManagerInterface $em, EmailService $emailService, PreferenceService $preferences ) {
		$this->em = $em;
		$this->email_service = $emailService;
		$this->preferences = $preferences;
	}

	/**
	 * Attempt to login
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
	 * Logout the current user
	 * @Route("/logout", name="app_logout", methods={"GET"})
	 */
	public function logout()
	{
		// controller can be blank: it will never be executed!
		throw new \Exception('Don\'t forget to activate logout in security.yaml');
	}


	/**
	 * Requests a password reset code for the given user
	 * @Route("/password_request", methods={"GET"})
	 * @return Response
	 */
	public function password_request( Request $request ) {

		$email = $request->query->get( 'email' );

		$user = $this->getUserByEmail( $email );

		if ( $user === null ) {
		}
		else {
			$user->setResetCode( base64_encode( random_bytes( 10 ) ) )
				->setResetCodeTimeout( new \DateTime( "now +10 minutes" ) );
			$this->em->persist( $user );
			$this->em->flush();

			$params = [
				'code' => $user->getResetCode(),
				'name' => $user->getName(),
			];
			$subject = $this->preferences->get('EML.PRS.SUB');
			$body = $this->preferences->get('EML.PRS.BDY');
			$this->email_service->send_email( $email, $user->getName(), $subject, $body, [], $params );
		}
		return new JsonResponse( [ "notes" => "Password reset instructions sent if your email address was found" ] );
	}

	/**
	 * Resets the password for the user, confirms reset code and timeout prior to changing
	 * @Route("/password_reset", methods={"POST"})
	 * @return Response
	 */
	public function password_reset( Request $request, UserPasswordEncoderInterface $passwordEncoder ) {

		$email = $request->request->get( 'email' );
		$code = $request->request->get( 'code' );
		$new_password = $request->request->get( 'password' );
		$now = new \DateTime( "now" );

		$user = $this->getUserByEmail( $email );

		// If there is no matching user
		if ( $user === null ) {
			return new JsonResponse( [ "status" => "Fail", "notes" => "Unable to find matching email address" ] );
		}
		else {
			if ( $user->getResetCode() !== $code || $user->getResetCodeTimeout() < $now ) {
				return new JsonResponse( [ "status" => "Fail", "notes" => "Your code is incorrect or expired" ] );
			}

			$user->setPassword( $passwordEncoder->encodePassword( $user, $new_password ) )
				->setResetCodeTimeout( null )
				->setResetCode( null );
			$this->em->persist( $user );
			$this->em->flush();

			return new JsonResponse( [ "status" => "OK", "notes" => "Your password has been reset" ] );
		}
	}

	/**
	 * Get the user related to the given email address
	 * @param $email
	 * @return User
	 * @throws \Doctrine\ORM\NonUniqueResultException
	 */
	private function getUserByEmail( $email ) {

		$qb = $this->em->createQueryBuilder();
		$qb->select( [ 'u' ] )
			->from( $this->userClassName, 'u' )
			->where( 'u.email like :email' )
			->setParameter( 'email', $email );
		/**
		 * @var $user User
		 */
		$user = $qb->getQuery()->setMaxResults( 1 )->getOneOrNullResult();

		return $user;
	}
}
