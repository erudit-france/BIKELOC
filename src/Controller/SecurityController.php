<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Routing\Annotation\Route;
use App\Entity\User;
use App\Repository\UserRepository;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Doctrine\Persistence\ManagerRegistry as PersistenceManagerRegistry;
use LogicException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\CsrfTokenBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\UserPassportInterface;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\HttpFoundation\JsonResponse;

class SecurityController extends AbstractController implements AuthenticatorInterface
{
    private $userRepository;
    private $googleID = "338533409329-qilrbipceigee7lokapbrjqdljob01mi.apps.googleusercontent.com";
    private $googleCODE = "FDuvqLQcuBS7xy4PmpHjNyRl";

    public function __construct(userRepository $userRepository)
    {
        $this->userRepository = $userRepository;
    }


    /**
     * @Route("/inscription", name="inscription")
     */
    public function inscription()
    {
        return $this->render('security/inscription.html.twig');
    }

    
    /**
     * @Route("/inscriptionUser", name="inscriptionUser", methods={"POST"})
     */
    public function inscriptionUser(Request $request, PersistenceManagerRegistry $managerRegistry)
    {
        $retourErreur = array();
        $form = json_decode(json_decode($request->request->get("PARAM"))->{'x'}->{'form'});
        $submittedToken = $form->token;
        $jsonData = new JsonData();
        if(!filter_var($form->email, FILTER_VALIDATE_EMAIL)) {
            $retourErreur[] = 'email';
            $jsonData->setData($retourErreur);
            $jsonData->setCode(2);
            $jsonData->setMessage("Erreur email invalide !");
            return new JsonResponse(json_encode($jsonData->jsonSerialize()));
        }
        if ($this->isCsrfTokenValid('delete-item', $submittedToken)) {
            $user = new User();
            $user->setRoles(['ROLE_USER']);
            $user->setName($form->prenom);
            $user->setUsername($form->nom);
            $user->setPhone($form->telephone);
            $user->setEmail($form->email);
            $user->setPassword($user->algoCryptage($form->password));
            $manager = $managerRegistry->getManager();
            $manager->persist($user);
            $manager->flush();
            $jsonData->setData(null);
            $jsonData->setCode(1);
            $jsonData->setMessage("Enregistrement réussi vous allez être redirigés sur votre compte !");
        }
        return new JsonResponse(json_encode($jsonData->jsonSerialize()));
    }

    /**
     * @Route("/logout", name="logout", methods={"GET"})
     */
    public function logout()
    {
    }

    /**
     * @Route("/connexion", name="connexion")
     */
    public function connexion(SessionInterface $session, $_route)
    {
        $user = new User();
        $form = $this->createFormBuilder($user)
        ->add('email')
        ->add('password', PasswordType::class)
        ->add('Connexion', SubmitType::class, [
            'attr' => [
                'class' => 'btn btn-primary'
            ]
        ])
        ->getForm();
        $form->handleRequest($requete);

        return $this->render(
            'guide/connexion.html.twig'
        );
    }
    /**
     * Does the authenticator support the given Request?
     *
     * If this returns false, the authenticator will be skipped.
     *
     * Returning null means authenticate() can be called lazily when accessing the token storage.
     */
    public function supports(Request $request): ?bool
    {
        // dump($request->attributes->get('_route') === 'connexion' && $request->isMethod('POST'));
        return $request->attributes->get('_route') === 'connexion' && $request->isMethod('POST');
    }

    /**
     * Create a passport for the current request.
     *
     * The passport contains the user, credentials and any additional information
     * that has to be checked by the Symfony Security system. For example, a login
     * form authenticator will probably return a passport containing the user, the
     * presented password and the CSRF token value.
     *
     * You may throw any AuthenticationException in this method in case of erreur (e.g.
     * a UsernameNotFoundException when the user cannot be found).
     *
     * @throws AuthenticationException
     */
    public function authenticate(Request $request): PassportInterface
    {
        // find a user based on an "email" form field
        // dump($this->userRepository);
        $user = $this->userRepository->findOneByEmail($request->request->get('username'));
        $request->getSession()->set('back_username', $request->request->get('username'));

        if (!$user) {
            throw new UsernameNotFoundException();
        }

        return new Passport($user, new PasswordCredentials($request->request->get('password')), [
            // and CSRF protection using a "csrf_token" field
            new CsrfTokenBadge('login', $request->request->get('csrf_token')),
            // new RememberMeBadge
        ]);
    }
    /**
     * Shortcut to create a PostAuthenticationToken for you, if you don't really
     * care about which authenticated token you're using.
     *
     * @return PostAuthenticationToken
     */
    public function createAuthenticatedToken(PassportInterface $passport, string $firewallName): TokenInterface
    {
        if (!$passport instanceof UserPassportInterface) {
            throw new LogicException(sprintf('Passport does not contain a user, overwrite "createAuthenticatedToken()" in "%s" to create a custom authenticated token.', \get_class($this)));
        }

        return new PostAuthenticationToken($passport->getUser(), $firewallName, $passport->getUser()->getRoles());
    }

    /**
     * Called when authentication executed and was succèssful!
     *
     * This should return the Response sent back to the user, like a
     * RedirectResponse to the last page they visited.
     *
     * If you return null, the current request will continue, and the user
     * will be authenticated. This makes sense, for example, with an API.
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        $sesion = new Session();
        $sesion = $sesion->get('lastUrl');
        $this->get('session')->getFlashBag()->add('succès', 'Connexion réussie!');

        if (isset($sesion['route'])) {
            if (isset($sesion['id'])) {
                if ($sesion['route'] == "Category") {
                    return $this->redirectToRoute($sesion['route'], [
                        'category' => $sesion['category'],
                        'id' => $sesion['id']
                    ]);
                }
                if ($sesion['route'] == "Search") {
                    return $this->redirectToRoute($sesion['route'], [
                        'search' => $sesion['search'],
                        'id' => $sesion['id']
                    ]);
                }
                return $this->redirectToRoute($sesion['route'], [
                    'id' => $sesion['id']
                ]);
            }
            return $this->redirectToRoute($sesion['route']);
        }
        return null;
    }

    /**
     * Called when authentication executed, but failed (e.g. wrong username password).
     *
     * This should return the Response sent back to the user, like a
     * RedirectResponse to the login page or a 403 response.
     *
     * If you return null, the request will continue, but the user will
     * not be authenticated. This is probably not what you want to do.
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $this->get('session')->getFlashBag()->add('erreur', 'Informations invalide!');
        return $this->redirectToRoute('connexion');
    }
}

class JsonData
{
    private $code;
    private $data;
    private $message;


    public function setCode($code)
    {
        $this->code = $code;
    }

    public function setData($data)
    {
        $this->data = $data;
    }

    public function setMessage($message)
    {
        $this->message = $message;
    }

    public function jsonSerialize()
    {
        return
            [
                'code'   => $this->code,
                'data' => $this->data,
                'message' => $this->message,
            ];
    }
}
