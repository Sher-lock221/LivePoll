package main

import (
	"context"
	"encoding/hex"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type app struct { users, polls, votes *mongo.Collection; redis *redis.Client; secret []byte }
type user struct { ID primitive.ObjectID `bson:"_id,omitempty"`; Email string `bson:"email"`; Password string `bson:"password"` }
type option struct { ID string `bson:"id" json:"id"`; Label string `bson:"label" json:"label"`; Votes int64 `bson:"votes" json:"votes"` }
type poll struct { ID primitive.ObjectID `bson:"_id,omitempty"`; Title string `bson:"title"`; Options []option `bson:"options"`; AuthorID primitive.ObjectID `bson:"authorId"`; CreatedAt time.Time `bson:"createdAt"` }
type vote struct { PollID primitive.ObjectID `bson:"pollId"`; VoterKey string `bson:"voterKey"`; OptionID string `bson:"optionId"`; CreatedAt time.Time `bson:"createdAt"` }
type pollResponse struct { ID string `json:"id"`; Title string `json:"title"`; Options []option `json:"options"`; CreatedAt time.Time `json:"createdAt"`; CanManage bool `json:"canManage"` }

func env(key, fallback string) string { if v := os.Getenv(key); v != "" { return v }; return fallback }
func redisOptions() *redis.Options { if raw:=os.Getenv("REDIS_URL"); raw!="" { opts,err:=redis.ParseURL(raw); if err!=nil { log.Fatal("Invalid REDIS_URL: ",err) }; return opts }; return &redis.Options{Addr:env("REDIS_ADDR","redis:6379")} }
func main() {
	ctx := context.Background()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(env("MONGO_URI", "mongodb://mongo:27017"))); if err != nil { log.Fatal(err) }
	db := client.Database(env("MONGO_DB", "livepoll"))
	a := &app{users: db.Collection("users"), polls: db.Collection("polls"), votes: db.Collection("votes"), redis: redis.NewClient(redisOptions()), secret: []byte(env("JWT_SECRET", "change-me-in-production"))}
	if err := a.redis.Ping(ctx).Err(); err != nil { log.Fatal(err) }
	_, _ = a.users.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key:"email", Value:1}}, Options: options.Index().SetUnique(true)})
	_, _ = a.votes.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key:"pollId", Value:1}, {Key:"voterKey", Value:1}}, Options: options.Index().SetUnique(true)})
	r := gin.New(); r.Use(gin.Logger(), gin.Recovery(), cors.New(cors.Config{AllowOrigins: strings.Split(env("CORS_ORIGINS", "http://localhost:5173"), ","), AllowMethods: []string{"GET","POST","OPTIONS"}, AllowHeaders: []string{"Authorization","Content-Type","X-Voter-ID"}, MaxAge: 12*time.Hour}))
	r.GET("/health", func(c *gin.Context) { c.JSON(200, gin.H{"ok":true}) })
	r.POST("/api/auth/signup", a.signup); r.POST("/api/auth/login", a.login)
	r.GET("/api/polls/:id", a.getPoll); r.GET("/api/polls/:id/events", a.events); r.POST("/api/polls/:id/votes", a.castVote)
	protected := r.Group("/api", a.requireAuth); protected.POST("/polls", a.createPoll); protected.GET("/mine", a.myPolls)
	log.Fatal(r.Run(":" + env("PORT", "8080")))
}
func emailOK(s string) bool { return len(s) <= 254 && strings.Count(s, "@") == 1 && len(strings.TrimSpace(s)) > 3 }
func (a *app) signup(c *gin.Context) { var in struct{ Email, Password string }; if c.ShouldBindJSON(&in)!=nil || !emailOK(in.Email) || len(in.Password)<8 || len(in.Password)>72 { c.JSON(400,gin.H{"error":"Use a valid email and a password of 8–72 characters."}); return }; h,_:=bcrypt.GenerateFromPassword([]byte(in.Password),bcrypt.DefaultCost); _,err:=a.users.InsertOne(c,bson.M{"email":strings.ToLower(strings.TrimSpace(in.Email)),"password":string(h)}); if mongo.IsDuplicateKeyError(err) { c.JSON(409,gin.H{"error":"An account already uses that email."}); return }; if err!=nil { c.JSON(500,gin.H{"error":"Could not create account."}); return }; a.loginWith(c, strings.ToLower(strings.TrimSpace(in.Email))) }
func (a *app) login(c *gin.Context) { var in struct{ Email, Password string }; if c.ShouldBindJSON(&in)!=nil { c.JSON(400,gin.H{"error":"Email and password are required."}); return }; var u user; err:=a.users.FindOne(c,bson.M{"email":strings.ToLower(strings.TrimSpace(in.Email))}).Decode(&u); if err!=nil || bcrypt.CompareHashAndPassword([]byte(u.Password),[]byte(in.Password))!=nil { c.JSON(401,gin.H{"error":"Incorrect email or password."}); return }; a.loginWith(c,u.Email) }
func (a *app) loginWith(c *gin.Context, email string) { var u user; _=a.users.FindOne(c,bson.M{"email":email}).Decode(&u); t:=jwt.NewWithClaims(jwt.SigningMethodHS256,jwt.MapClaims{"sub":u.ID.Hex(),"exp":time.Now().Add(7*24*time.Hour).Unix()}); signed,_:=t.SignedString(a.secret); c.JSON(200,gin.H{"token":signed,"email":u.Email}) }
func (a *app) requireAuth(c *gin.Context) { raw:=strings.TrimPrefix(c.GetHeader("Authorization"),"Bearer "); t,err:=jwt.Parse(raw,func(t *jwt.Token)(interface{},error){if _,ok:=t.Method.(*jwt.SigningMethodHMAC);!ok{return nil,errors.New("bad token")};return a.secret,nil}); if err!=nil||!t.Valid { c.AbortWithStatusJSON(401,gin.H{"error":"Please sign in."});return }; claims,ok:=t.Claims.(jwt.MapClaims); sub,ok2:=claims["sub"].(string); if !ok||!ok2 { c.AbortWithStatusJSON(401,gin.H{"error":"Please sign in."});return }; id,err:=primitive.ObjectIDFromHex(sub); if err!=nil { c.AbortWithStatusJSON(401,gin.H{"error":"Please sign in."});return }; c.Set("userID",id); c.Next() }
func (a *app) createPoll(c *gin.Context) { var in struct { Title string `json:"title"`; Options []string `json:"options"` }; if c.ShouldBindJSON(&in)!=nil { c.JSON(400,gin.H{"error":"Invalid poll."});return }; in.Title=strings.TrimSpace(in.Title); if len(in.Title)<3||len(in.Title)>140||len(in.Options)<2||len(in.Options)>8 { c.JSON(400,gin.H{"error":"Title must be 3–140 characters with 2–8 choices."});return }; opts:=make([]option,0,len(in.Options)); seen:=map[string]bool{}; for _,label:=range in.Options { label=strings.TrimSpace(label); key:=strings.ToLower(label); if len(label)<1||len(label)>80||seen[key] {c.JSON(400,gin.H{"error":"Choices must be unique and 1–80 characters."});return};seen[key]=true;opts=append(opts,option{ID:uuid.NewString(),Label:label}) }; p:=poll{Title:in.Title,Options:opts,AuthorID:c.MustGet("userID").(primitive.ObjectID),CreatedAt:time.Now().UTC()}; result,err:=a.polls.InsertOne(c,&p);if err!=nil{c.JSON(500,gin.H{"error":"Could not save poll."});return};p.ID=result.InsertedID.(primitive.ObjectID); _=a.setCounts(c,&p); c.JSON(201,a.response(c,&p,p.AuthorID)) }
func (a *app) getPoll(c *gin.Context) { p,ok:=a.findPoll(c);if !ok{return}; c.JSON(200,a.response(c,p,primitive.NilObjectID)) }
func (a *app) myPolls(c *gin.Context) { uid:=c.MustGet("userID").(primitive.ObjectID); cur,err:=a.polls.Find(c,bson.M{"authorId":uid},options.Find().SetSort(bson.D{{Key:"createdAt",Value:-1}}));if err!=nil{c.JSON(500,gin.H{"error":"Could not load polls."});return};defer cur.Close(c); out:=[]pollResponse{};for cur.Next(c){var p poll;if cur.Decode(&p)==nil{out=append(out,a.response(c,&p,uid))}};c.JSON(200,out) }
func (a *app) castVote(c *gin.Context) { p,ok:=a.findPoll(c);if !ok{return}; var in struct{ OptionID string `json:"optionId"`}; if c.ShouldBindJSON(&in)!=nil {c.JSON(400,gin.H{"error":"Choose an option."});return}; valid:=false;for _,o:=range p.Options{if o.ID==in.OptionID{valid=true}}; if !valid{c.JSON(400,gin.H{"error":"That option is not part of this poll."});return}; voter:=c.GetHeader("X-Voter-ID");if _,err:=uuid.Parse(voter);err!=nil{c.JSON(400,gin.H{"error":"Invalid voter identifier."});return}; digest:=sha256.Sum256([]byte(voter)); _,err:=a.votes.InsertOne(c,vote{PollID:p.ID,VoterKey:hex.EncodeToString(digest[:]),OptionID:in.OptionID,CreatedAt:time.Now().UTC()});if mongo.IsDuplicateKeyError(err){c.JSON(409,gin.H{"error":"You have already voted on this poll."});return};if err!=nil{c.JSON(500,gin.H{"error":"Could not record vote."});return}; _,err=a.polls.UpdateOne(c,bson.M{"_id":p.ID},bson.M{"$inc":bson.M{"options.$[choice].votes":1}},options.Update().SetArrayFilters(options.ArrayFilters{Filters:[]interface{}{bson.M{"choice.id":in.OptionID}}}));if err!=nil{_,_=a.votes.DeleteOne(c,bson.M{"pollId":p.ID,"voterKey":hex.EncodeToString(digest[:])});c.JSON(500,gin.H{"error":"Could not tally vote."});return}; count,err:=a.redis.HIncrBy(c,"poll:"+p.ID.Hex()+":counts",in.OptionID,1).Result();if err!=nil{_,_=a.votes.DeleteOne(c,bson.M{"pollId":p.ID,"voterKey":hex.EncodeToString(digest[:])});_,_=a.polls.UpdateOne(c,bson.M{"_id":p.ID},bson.M{"$inc":bson.M{"options.$[choice].votes":-1}},options.Update().SetArrayFilters(options.ArrayFilters{Filters:[]interface{}{bson.M{"choice.id":in.OptionID}}}));c.JSON(503,gin.H{"error":"Live count unavailable; please try again."});return}; _=count; payload,_:=json.Marshal(a.counts(c,p)); _=a.redis.Publish(c,"poll:"+p.ID.Hex()+":events",payload).Err(); c.JSON(201,gin.H{"ok":true}) }
func (a *app) events(c *gin.Context) { p,ok:=a.findPoll(c);if !ok{return}; c.Header("Content-Type","text/event-stream");c.Header("Cache-Control","no-cache");c.Header("Connection","keep-alive"); sub:=a.redis.Subscribe(c,"poll:"+p.ID.Hex()+":events");defer sub.Close(); fmt:=func(data []byte){c.SSEvent("results",string(data));c.Writer.Flush()}; initial,_:=json.Marshal(a.counts(c,p));fmt(initial);ch:=sub.Channel();for{select{case msg:=<-ch:if msg!=nil{fmt([]byte(msg.Payload))};case <-c.Request.Context().Done():return}} }
func (a *app) findPoll(c *gin.Context)(*poll,bool){id,err:=primitive.ObjectIDFromHex(c.Param("id"));if err!=nil{c.JSON(404,gin.H{"error":"Poll not found."});return nil,false};var p poll;if a.polls.FindOne(c,bson.M{"_id":id}).Decode(&p)!=nil{c.JSON(404,gin.H{"error":"Poll not found."});return nil,false};return &p,true}
func (a *app) setCounts(c context.Context,p *poll)error{values:=map[string]interface{}{};for _,o:=range p.Options{values[o.ID]=o.Votes};return a.redis.HSet(c,"poll:"+p.ID.Hex()+":counts",values).Err()}
func (a *app) counts(c context.Context,p *poll)map[string]int64{key:="poll:"+p.ID.Hex()+":counts"; vals,err:=a.redis.HGetAll(c,key).Result();if err!=nil||len(vals)==0{_ = a.setCounts(c,p);vals,_=a.redis.HGetAll(c,key).Result()};out:=map[string]int64{};for _,o:=range p.Options{var n int64;_,_=fmtSscan(vals[o.ID],&n);out[o.ID]=n};return out}
func fmtSscan(s string,n *int64)(int,error){ var x int64; for _,ch:=range s { if ch<'0'||ch>'9'{continue};x=x*10+int64(ch-'0') };*n=x;return 1,nil }
func (a *app) response(c context.Context,p *poll,viewer primitive.ObjectID)pollResponse{out:=pollResponse{ID:p.ID.Hex(),Title:p.Title,Options:append([]option(nil),p.Options...),CreatedAt:p.CreatedAt,CanManage:viewer==p.AuthorID};counts:=a.counts(c,p);for i:=range out.Options{out.Options[i].Votes=counts[out.Options[i].ID]};return out}
