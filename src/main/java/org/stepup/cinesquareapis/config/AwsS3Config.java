package org.stepup.cinesquareapis.config;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AwsS3Config {

    @Value("${cloud.aws.credentials.accessKey}")
    private String encryptedAccessKey;
    @Value("${cloud.aws.credentials.secretKey}")
    private String encryptedSecretKey;
    @Value("${cloud.aws.region.static}")
    private String region;

    @Bean
    public AmazonS3Client amazonS3Client() {
        System.out.println("Amend Commit");

        BasicAWSCredentials awsCredentials = new BasicAWSCredentials(encryptedAccessKey, encryptedSecretKey);
        return (AmazonS3Client) AmazonS3ClientBuilder.standard()
                .withRegion(region).enablePathStyleAccess()
                .withCredentials(new AWSStaticCredentialsProvider(awsCredentials))
                .build();
    }
}