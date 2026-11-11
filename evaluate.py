"""Run classifier evaluation (0.5 cutoff), the deployed-policy evaluation (0.42/0.72 + rules) and the six-scenario agent benchmark."""
import evaluate_classifier
import evaluate_agent
import evaluate_policy
if __name__ == "__main__":
    evaluate_classifier.main()
    evaluate_agent.main()
    evaluate_policy.main([])
